//! Notification channel configuration. Each variant maps to one `Notifier` impl.

use super::secret::Secret;
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;

fn default_batch_window() -> Duration {
    Duration::from_secs(15 * 60)
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SmtpTls {
    /// Port 587: plaintext connect, then upgrade. Refuses to continue if the server
    /// does not offer STARTTLS.
    Starttls,
    /// Port 465: TLS from the first byte.
    Implicit,
    /// Only sane for a local sink such as mailpit in docker-compose.
    None,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    pub host: String,
    #[serde(default = "default_smtp_port")]
    pub port: u16,
    #[serde(default = "default_smtp_tls")]
    pub tls: SmtpTls,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<Secret>,
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    pub from: String,
    pub to: Vec<String>,
}

fn default_smtp_port() -> u16 {
    587
}
fn default_smtp_tls() -> SmtpTls {
    SmtpTls::Starttls
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub url: String,
    #[serde(default)]
    pub headers: std::collections::BTreeMap<String, String>,
    /// When set, the body is signed and sent as `X-Vedette-Signature: sha256=<hex>`.
    #[serde(default)]
    pub hmac_secret: Option<Secret>,
    #[serde(default)]
    pub hmac_secret_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NtfyConfig {
    #[serde(default = "default_ntfy_base")]
    pub base_url: String,
    pub topic: String,
    #[serde(default)]
    pub token: Option<Secret>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
}

fn default_ntfy_base() -> String {
    "https://ntfy.sh".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GotifyConfig {
    pub base_url: String,
    #[serde(default)]
    pub token: Option<Secret>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    #[serde(default)]
    pub token: Option<Secret>,
    #[serde(default)]
    pub token_file: Option<PathBuf>,
    pub chat_id: String,
    #[serde(default = "default_telegram_api")]
    pub api_base: String,
}

fn default_telegram_api() -> String {
    "https://api.telegram.org".to_string()
}

/// How the `file` channel writes each batch.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FileFormat {
    /// The same plain-text digest the email carries, under a timestamped header.
    #[default]
    Text,
    /// One JSON object per alert per line, for `jq` or `tail -f | jq`.
    Jsonl,
}

/// A development channel: appends every batch to a local file instead of sending it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub path: PathBuf,
    #[serde(default)]
    pub format: FileFormat,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum ChannelKind {
    Smtp(SmtpConfig),
    Webhook(WebhookConfig),
    Ntfy(NtfyConfig),
    Gotify(GotifyConfig),
    Telegram(TelegramConfig),
    File(FileConfig),
}

#[derive(Debug, Clone, Deserialize)]
pub struct ChannelConfig {
    pub name: String,
    #[serde(default = "super::watch::default_true_pub")]
    pub enabled: bool,
    /// Alerts are held this long so one poll cycle produces one digest, not forty emails.
    #[serde(default = "default_batch_window", with = "humantime_serde")]
    pub batch_window: Duration,
    /// KEV additions and CRITICAL findings bypass `batch_window`.
    #[serde(default = "super::watch::default_true_pub")]
    pub urgent_immediate: bool,
    #[serde(flatten)]
    pub kind: ChannelKind,
}

impl ChannelConfig {
    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            ChannelKind::Smtp(_) => "smtp",
            ChannelKind::Webhook(_) => "webhook",
            ChannelKind::Ntfy(_) => "ntfy",
            ChannelKind::Gotify(_) => "gotify",
            ChannelKind::Telegram(_) => "telegram",
            ChannelKind::File(_) => "file",
        }
    }
}
