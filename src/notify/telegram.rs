//! Telegram bot messages.

use super::{render, NotifyError, Notifier};
use crate::config::{channel::TelegramConfig, secret};
use crate::pipeline::Alert;
use anyhow::Result;
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

/// Telegram rejects a `sendMessage` body over 4096 characters outright, so a long digest
/// has to be split across several messages. A little headroom covers the HTML tags added
/// during escaping.
pub const MAX_MESSAGE_CHARS: usize = 3_900;

pub struct TelegramNotifier {
    name: String,
    http: reqwest::Client,
    api_base: String,
    token: SecretString,
    chat_id: String,
}

impl TelegramNotifier {
    pub fn new(name: &str, cfg: &TelegramConfig, http: reqwest::Client) -> Result<Self> {
        let token = secret::pick("token", cfg.token.as_ref(), cfg.token_file.as_ref())?
            .ok_or_else(|| anyhow::anyhow!("telegram requires `token` or `token_file`"))?;
        if cfg.chat_id.trim().is_empty() {
            anyhow::bail!("`chat_id` must not be empty");
        }
        Ok(Self {
            name: name.to_string(),
            http,
            api_base: cfg.api_base.trim_end_matches('/').to_string(),
            token,
            chat_id: cfg.chat_id.clone(),
        })
    }

    /// Escapes the five characters Telegram's HTML parse mode cares about.
    ///
    /// HTML mode is used rather than MarkdownV2 deliberately: MarkdownV2 requires
    /// escaping some eighteen characters, and a single missed one makes Telegram reject
    /// the whole message with a 400.
    pub fn escape(s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }

    pub fn format(batch: &[Alert]) -> Vec<String> {
        let mut body = format!("<b>{}</b>\n\n", Self::escape(&render::heading(batch)));
        for a in batch {
            let sev = a.severity.as_deref().unwrap_or("unscored");
            body.push_str(&format!(
                "{} <a href=\"{}\">{}</a> — {}\n<i>{}</i>\n{}\n",
                if a.urgent { "\u{1F6A8}" } else { "\u{1F512}" },
                Self::escape(&a.url),
                Self::escape(&a.cve_id),
                Self::escape(sev),
                Self::escape(&a.event.detail),
                Self::escape(&a.watch),
            ));
            if a.in_kev {
                body.push_str(&format!(
                    "<b>KEV</b>: actively exploited{}\n",
                    a.kev_due_date
                        .as_deref()
                        .map(|d| format!(", due {}", Self::escape(d)))
                        .unwrap_or_default()
                ));
            }
            body.push('\n');
        }
        render::chunk(&body, MAX_MESSAGE_CHARS)
    }
}

#[async_trait]
impl Notifier for TelegramNotifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "telegram"
    }

    async fn send(&self, batch: &[Alert]) -> Result<(), NotifyError> {
        if batch.is_empty() {
            return Ok(());
        }
        let url = format!(
            "{}/bot{}/sendMessage",
            self.api_base,
            self.token.expose_secret()
        );
        for part in Self::format(batch) {
            let resp = self
                .http
                .post(&url)
                .json(&serde_json::json!({
                    "chat_id": self.chat_id,
                    "text": part,
                    "parse_mode": "HTML",
                    "disable_web_page_preview": true,
                }))
                .send()
                .await?;
            let status = resp.status();
            if !status.is_success() {
                let text = resp.text().await.unwrap_or_default();
                // 429 carries `parameters.retry_after`; the outbox backoff handles the
                // wait, so this only has to classify it as retryable.
                return Err(NotifyError::from_status(status, text));
            }
        }
        tracing::info!(channel = %self.name, items = batch.len(), "telegram message sent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;
    use crate::events::EventKind;
    use crate::notify::render::tests::alert;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(base: String) -> TelegramConfig {
        TelegramConfig {
            token: Some(Secret::Interpolated("123:ABC".into())),
            token_file: None,
            chat_id: "-1001234567890".into(),
            api_base: base,
        }
    }

    #[test]
    fn escapes_html_special_characters() {
        assert_eq!(
            TelegramNotifier::escape("a<b>&\"c'"),
            "a&lt;b&gt;&amp;&quot;c&#39;"
        );
    }

    #[test]
    fn a_hostile_description_cannot_inject_markup() {
        let mut b = vec![alert("CVE-1", "nginx", EventKind::New, Some("HIGH"))];
        b[0].event.detail = "<script>alert(1)</script>".into();
        let parts = TelegramNotifier::format(&b);
        assert!(!parts[0].contains("<script>"), "{}", parts[0]);
        assert!(parts[0].contains("&lt;script&gt;"));
    }

    #[test]
    fn a_long_digest_is_split_under_the_limit() {
        let b: Vec<Alert> = (0..300)
            .map(|i| alert(&format!("CVE-2026-{i}"), "nginx", EventKind::New, Some("HIGH")))
            .collect();
        let parts = TelegramNotifier::format(&b);
        assert!(parts.len() > 1, "a 300-alert digest must be split");
        for p in &parts {
            assert!(
                p.chars().count() <= 4096,
                "part of {} chars exceeds Telegram's hard limit",
                p.chars().count()
            );
        }
    }

    #[tokio::test]
    async fn posts_to_sendmessage_with_html_parse_mode() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/bot123:ABC/sendMessage"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let n = TelegramNotifier::new("tg", &cfg(server.uri()), crate::sources::http_client().unwrap())
            .unwrap();
        n.send(&[alert("CVE-2026-1", "nginx", EventKind::KevAdded, Some("CRITICAL"))])
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["parse_mode"], "HTML");
        assert_eq!(body["chat_id"], "-1001234567890");
        assert!(body["text"].as_str().unwrap().contains("CVE-2026-1"));
        assert!(body["text"].as_str().unwrap().contains("<b>KEV</b>"));
    }

    #[tokio::test]
    async fn every_chunk_is_delivered() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"ok": true})))
            .mount(&server)
            .await;

        let b: Vec<Alert> = (0..300)
            .map(|i| alert(&format!("CVE-2026-{i}"), "nginx", EventKind::New, Some("HIGH")))
            .collect();
        let expected = TelegramNotifier::format(&b).len();
        let n = TelegramNotifier::new("tg", &cfg(server.uri()), crate::sources::http_client().unwrap())
            .unwrap();
        n.send(&b).await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), expected);
    }

    #[tokio::test]
    async fn a_429_is_retryable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(429).set_body_json(
                serde_json::json!({"ok": false, "parameters": {"retry_after": 30}}),
            ))
            .mount(&server)
            .await;
        let n = TelegramNotifier::new("tg", &cfg(server.uri()), crate::sources::http_client().unwrap())
            .unwrap();
        let err = n
            .send(&[alert("CVE-1", "nginx", EventKind::New, Some("HIGH"))])
            .await
            .unwrap_err();
        assert!(err.is_retryable());
    }

    #[test]
    fn an_empty_chat_id_is_rejected() {
        let mut c = cfg("https://api.telegram.org".into());
        c.chat_id = " ".into();
        assert!(TelegramNotifier::new("tg", &c, crate::sources::http_client().unwrap()).is_err());
    }
}
