//! Gotify push notifications (self-hosted).

use super::{render, NotifyError, Notifier};
use crate::config::{channel::GotifyConfig, secret};
use crate::events::EventKind;
use crate::pipeline::Alert;
use anyhow::Result;
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

pub struct GotifyNotifier {
    name: String,
    http: reqwest::Client,
    url: String,
    token: SecretString,
}

impl GotifyNotifier {
    pub fn new(name: &str, cfg: &GotifyConfig, http: reqwest::Client) -> Result<Self> {
        let token = secret::pick("token", cfg.token.as_ref(), cfg.token_file.as_ref())?
            .ok_or_else(|| anyhow::anyhow!("gotify requires `token` or `token_file`"))?;
        Ok(Self {
            name: name.to_string(),
            http,
            url: format!("{}/message", cfg.base_url.trim_end_matches('/')),
            token,
        })
    }

    /// Gotify priority 0-10; 8 and above triggers a device alert in most clients.
    fn priority(batch: &[Alert]) -> u8 {
        if batch.iter().any(|a| a.event.kind == EventKind::KevAdded) {
            9
        } else if batch.iter().any(|a| a.urgent) {
            7
        } else {
            5
        }
    }
}

#[async_trait]
impl Notifier for GotifyNotifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "gotify"
    }

    async fn send(&self, batch: &[Alert]) -> Result<(), NotifyError> {
        if batch.is_empty() {
            return Ok(());
        }
        let body = serde_json::json!({
            "title": render::heading(batch),
            "message": render::markdown(batch, 10),
            "priority": Self::priority(batch),
            // Without this Gotify renders the message as plain text and eats the links.
            "extras": {"client::display": {"contentType": "text/markdown"}},
        });
        let resp = self
            .http
            .post(&self.url)
            // Gotify accepts the app token as a query parameter or this header; the
            // header keeps it out of the server's access log.
            .header("X-Gotify-Key", self.token.expose_secret())
            .json(&body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(NotifyError::from_status(status, text));
        }
        tracing::info!(channel = %self.name, items = batch.len(), "gotify push sent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;
    use crate::notify::render::tests::alert;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(base: String) -> GotifyConfig {
        GotifyConfig {
            base_url: base,
            token: Some(Secret::Interpolated("A-token".into())),
            token_file: None,
        }
    }

    #[test]
    fn priority_escalates_for_kev() {
        assert_eq!(
            GotifyNotifier::priority(&[alert("C", "w", EventKind::KevAdded, Some("HIGH"))]),
            9
        );
        assert_eq!(
            GotifyNotifier::priority(&[alert("C", "w", EventKind::ExploitRef, Some("HIGH"))]),
            7
        );
        assert_eq!(
            GotifyNotifier::priority(&[alert("C", "w", EventKind::New, Some("LOW"))]),
            5
        );
    }

    #[test]
    fn a_missing_token_is_a_config_error() {
        let mut c = cfg("https://gotify.test".into());
        c.token = None;
        let err = GotifyNotifier::new("g", &c, crate::sources::http_client().unwrap())
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("requires `token`"), "{err}");
    }

    #[tokio::test]
    async fn posts_a_markdown_message_with_the_key_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/message"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"id": 1})))
            .mount(&server)
            .await;

        let n = GotifyNotifier::new("g", &cfg(server.uri()), crate::sources::http_client().unwrap())
            .unwrap();
        n.send(&[alert("CVE-2026-1", "nginx", EventKind::KevAdded, Some("CRITICAL"))])
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(
            reqs[0].headers.get("x-gotify-key").and_then(|v| v.to_str().ok()),
            Some("A-token")
        );
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["priority"], 9);
        assert_eq!(
            body["extras"]["client::display"]["contentType"],
            "text/markdown"
        );
        assert!(body["message"].as_str().unwrap().contains("CVE-2026-1"));
    }
}
