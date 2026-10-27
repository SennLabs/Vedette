//! Notification channels.
//!
//! Every channel implements one trait, and the outbox dispatcher neither knows nor cares
//! which it is talking to. The error classification is the part that matters: a
//! retryable failure (connection reset, 503, SMTP 4xx) earns a backoff, a permanent one
//! (bad token, 400) retires the row immediately rather than hammering a misconfigured
//! endpoint for hours.

pub mod file;
pub mod gotify;
pub mod ntfy;
pub mod render;
pub mod smtp;
pub mod telegram;
pub mod webhook;

use crate::config::{ChannelConfig, ChannelKind, Settings};
use crate::pipeline::Alert;
use anyhow::Result;
use async_trait::async_trait;
use std::collections::BTreeMap;
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    /// Worth another attempt: network trouble, a 5xx, a rate limit.
    #[error("{0}")]
    Retryable(#[source] anyhow::Error),
    /// Hopeless without a config change: bad credentials, a rejected payload.
    #[error("{0}")]
    Permanent(#[source] anyhow::Error),
}

impl NotifyError {
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }

    /// Classifies an HTTP status the way the outbox needs.
    ///
    /// 401/403 are treated as permanent: for a webhook or bot token they mean the
    /// credential is wrong, and retrying cannot fix that. (NVD's use of 403 for
    /// throttling is handled separately in the NVD client, which has the context to know.)
    pub fn from_status(status: reqwest::StatusCode, body: String) -> Self {
        let e = anyhow::anyhow!("HTTP {status}: {}", body.chars().take(400).collect::<String>());
        if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            Self::Retryable(e)
        } else {
            Self::Permanent(e)
        }
    }
}

impl From<reqwest::Error> for NotifyError {
    fn from(e: reqwest::Error) -> Self {
        // A transport-level failure is almost always worth one more try.
        Self::Retryable(e.into())
    }
}

#[async_trait]
pub trait Notifier: Send + Sync {
    fn name(&self) -> &str;
    fn kind(&self) -> &'static str;
    /// Delivers a whole batch as one message where the medium allows it.
    async fn send(&self, batch: &[Alert]) -> Result<(), NotifyError>;
}

/// Builds every enabled channel from the config, resolving secrets once at startup so a
/// missing environment variable fails immediately rather than on the first alert.
pub fn build(settings: &Settings) -> Result<BTreeMap<String, Arc<dyn Notifier>>> {
    let http = crate::sources::http_client()?;
    let mut out: BTreeMap<String, Arc<dyn Notifier>> = BTreeMap::new();
    for c in settings.channel.iter().filter(|c| c.enabled) {
        out.insert(c.name.clone(), build_one(c, &http)?);
    }
    Ok(out)
}

/// `build`, unless `notify.dry_run` is set, in which case every enabled channel becomes a
/// [`DryRunNotifier`]. Both the daemon and `notify drain` go through here so a config
/// that says "never send" is honoured by every path that could send.
pub fn build_for(settings: &Settings) -> Result<BTreeMap<String, Arc<dyn Notifier>>> {
    if !settings.notify.dry_run {
        return build(settings);
    }
    tracing::warn!("notify.dry_run is set: alerts will be logged, not delivered");
    Ok(settings
        .channel
        .iter()
        .filter(|c| c.enabled)
        .map(|c| {
            let n: Arc<dyn Notifier> = Arc::new(DryRunNotifier::new(c.name.clone()));
            (c.name.clone(), n)
        })
        .collect())
}

pub fn build_one(c: &ChannelConfig, http: &reqwest::Client) -> Result<Arc<dyn Notifier>> {
    use anyhow::Context;
    let made: Arc<dyn Notifier> = match &c.kind {
        ChannelKind::Smtp(cfg) => Arc::new(
            smtp::SmtpNotifier::new(&c.name, cfg)
                .with_context(|| format!("channel `{}`", c.name))?,
        ),
        ChannelKind::Webhook(cfg) => Arc::new(
            webhook::WebhookNotifier::new(&c.name, cfg, http.clone())
                .with_context(|| format!("channel `{}`", c.name))?,
        ),
        ChannelKind::Ntfy(cfg) => Arc::new(
            ntfy::NtfyNotifier::new(&c.name, cfg, http.clone())
                .with_context(|| format!("channel `{}`", c.name))?,
        ),
        ChannelKind::Gotify(cfg) => Arc::new(
            gotify::GotifyNotifier::new(&c.name, cfg, http.clone())
                .with_context(|| format!("channel `{}`", c.name))?,
        ),
        ChannelKind::Telegram(cfg) => Arc::new(
            telegram::TelegramNotifier::new(&c.name, cfg, http.clone())
                .with_context(|| format!("channel `{}`", c.name))?,
        ),
        ChannelKind::File(cfg) => Arc::new(
            file::FileNotifier::new(&c.name, cfg)
                .with_context(|| format!("channel `{}`", c.name))?,
        ),
    };
    Ok(made)
}

/// A notifier that records instead of sending. Used by `notify.dry_run` and by tests.
pub struct DryRunNotifier {
    pub name: String,
    pub sent: std::sync::Mutex<Vec<Vec<Alert>>>,
}

impl DryRunNotifier {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            sent: std::sync::Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl Notifier for DryRunNotifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "dry-run"
    }
    async fn send(&self, batch: &[Alert]) -> Result<(), NotifyError> {
        tracing::info!(
            channel = %self.name,
            items = batch.len(),
            "dry run: would have delivered {} alert(s)",
            batch.len()
        );
        self.sent.lock().unwrap().push(batch.to_vec());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_errors_retry_and_client_errors_do_not() {
        use reqwest::StatusCode;
        assert!(NotifyError::from_status(StatusCode::INTERNAL_SERVER_ERROR, String::new())
            .is_retryable());
        assert!(NotifyError::from_status(StatusCode::SERVICE_UNAVAILABLE, String::new())
            .is_retryable());
        assert!(NotifyError::from_status(StatusCode::TOO_MANY_REQUESTS, String::new())
            .is_retryable());
        // A wrong token must not be retried for hours.
        assert!(!NotifyError::from_status(StatusCode::UNAUTHORIZED, String::new()).is_retryable());
        assert!(!NotifyError::from_status(StatusCode::FORBIDDEN, String::new()).is_retryable());
        assert!(!NotifyError::from_status(StatusCode::BAD_REQUEST, String::new()).is_retryable());
    }

    #[test]
    fn error_bodies_are_truncated_so_a_log_line_stays_readable() {
        let e = NotifyError::from_status(reqwest::StatusCode::BAD_REQUEST, "x".repeat(5_000));
        assert!(e.to_string().len() < 500);
    }
}
