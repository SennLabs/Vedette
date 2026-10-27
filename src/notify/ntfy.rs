//! ntfy push notifications (ntfy.sh or self-hosted).

use super::{render, NotifyError, Notifier};
use crate::config::{channel::NtfyConfig, secret};
use crate::events::EventKind;
use crate::pipeline::Alert;
use anyhow::Result;
use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};

pub struct NtfyNotifier {
    name: String,
    http: reqwest::Client,
    url: String,
    token: Option<SecretString>,
}

impl NtfyNotifier {
    pub fn new(name: &str, cfg: &NtfyConfig, http: reqwest::Client) -> Result<Self> {
        if cfg.topic.trim().is_empty() {
            anyhow::bail!("`topic` must not be empty");
        }
        Ok(Self {
            name: name.to_string(),
            http,
            url: format!("{}/{}", cfg.base_url.trim_end_matches('/'), cfg.topic),
            token: secret::pick("token", cfg.token.as_ref(), cfg.token_file.as_ref())?,
        })
    }

    /// ntfy priorities run 1 (min) to 5 (max). An actively exploited vulnerability earns
    /// the one that bypasses a phone's quiet hours.
    fn priority(batch: &[Alert]) -> &'static str {
        if batch.iter().any(|a| a.event.kind == EventKind::KevAdded) {
            "urgent"
        } else if batch.iter().any(|a| a.urgent) {
            "high"
        } else {
            "default"
        }
    }

    fn tags(batch: &[Alert]) -> String {
        let mut tags = vec!["shield"];
        if batch.iter().any(|a| a.in_kev) {
            tags.push("fire");
        }
        if batch.iter().any(|a| a.kev_ransomware) {
            tags.push("lock");
        }
        tags.join(",")
    }
}

#[async_trait]
impl Notifier for NtfyNotifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "ntfy"
    }

    async fn send(&self, batch: &[Alert]) -> Result<(), NotifyError> {
        if batch.is_empty() {
            return Ok(());
        }
        // Push payloads are read on a phone; a long digest is useless there.
        let body = render::markdown(batch, 10);
        let mut req = self
            .http
            .post(&self.url)
            // Header values must be visible ASCII; the heading contains an em dash.
            .header("Title", render::ascii_header(&render::heading(batch)))
            .header("Priority", Self::priority(batch))
            .header("Tags", Self::tags(batch))
            .header("Markdown", "yes");
        if let Some(t) = &self.token {
            req = req.bearer_auth(t.expose_secret());
        }
        // Deep-link straight to the CVE when the batch is a single alert.
        if batch.len() == 1 {
            req = req.header("Click", batch[0].url.clone());
        }

        let resp = req.body(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(NotifyError::from_status(status, text));
        }
        tracing::info!(channel = %self.name, items = batch.len(), "ntfy push sent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notify::render::tests::alert;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(base: String) -> NtfyConfig {
        NtfyConfig {
            base_url: base,
            topic: "vedette-kev".into(),
            token: None,
            token_file: None,
        }
    }

    #[test]
    fn kev_gets_the_urgent_priority() {
        let kev = vec![alert("CVE-1", "nginx", EventKind::KevAdded, Some("HIGH"))];
        assert_eq!(NtfyNotifier::priority(&kev), "urgent");

        let exploit = vec![alert("CVE-2", "nginx", EventKind::ExploitRef, Some("HIGH"))];
        assert_eq!(NtfyNotifier::priority(&exploit), "high");

        let plain = vec![alert("CVE-3", "nginx", EventKind::New, Some("LOW"))];
        assert_eq!(NtfyNotifier::priority(&plain), "default");
    }

    #[test]
    fn tags_reflect_kev_and_ransomware() {
        let mut b = vec![alert("CVE-1", "nginx", EventKind::New, Some("HIGH"))];
        b[0].in_kev = false;
        b[0].kev_ransomware = false;
        assert_eq!(NtfyNotifier::tags(&b), "shield");

        b[0].in_kev = true;
        b[0].kev_ransomware = true;
        assert_eq!(NtfyNotifier::tags(&b), "shield,fire,lock");
    }

    #[tokio::test]
    async fn posts_to_the_topic_with_the_expected_headers() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/vedette-kev"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let n = NtfyNotifier::new("push", &cfg(server.uri()), crate::sources::http_client().unwrap())
            .unwrap();
        n.send(&[alert("CVE-2026-1", "nginx", EventKind::KevAdded, Some("CRITICAL"))])
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        let h = |k: &str| reqs[0].headers.get(k).and_then(|v| v.to_str().ok()).map(str::to_owned);
        assert_eq!(h("priority").as_deref(), Some("urgent"));
        assert_eq!(h("markdown").as_deref(), Some("yes"));
        let title = h("title").expect("the Title header must be readable ASCII");
        assert!(title.starts_with("[KEV]"), "{title}");
        assert!(title.is_ascii(), "a header value must be ASCII: {title}");
        // A single alert deep-links to the CVE.
        assert_eq!(
            h("click").as_deref(),
            Some("https://nvd.nist.gov/vuln/detail/CVE-2026-1")
        );
        assert!(String::from_utf8_lossy(&reqs[0].body).contains("CVE-2026-1"));
    }

    #[tokio::test]
    async fn a_token_becomes_a_bearer_header() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let mut c = cfg(server.uri());
        c.token = Some(crate::config::Secret::Interpolated("tk_abc".into()));
        let n = NtfyNotifier::new("push", &c, crate::sources::http_client().unwrap()).unwrap();
        n.send(&[alert("CVE-1", "nginx", EventKind::New, Some("HIGH"))])
            .await
            .unwrap();
        let reqs = server.received_requests().await.unwrap();
        assert_eq!(
            reqs[0].headers.get("authorization").and_then(|v| v.to_str().ok()),
            Some("Bearer tk_abc")
        );
    }

    #[tokio::test]
    async fn no_click_header_for_a_digest() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let n = NtfyNotifier::new("push", &cfg(server.uri()), crate::sources::http_client().unwrap())
            .unwrap();
        n.send(&[
            alert("CVE-1", "nginx", EventKind::New, Some("HIGH")),
            alert("CVE-2", "nginx", EventKind::New, Some("HIGH")),
        ])
        .await
        .unwrap();
        let reqs = server.received_requests().await.unwrap();
        assert!(reqs[0].headers.get("click").is_none());
    }

    #[test]
    fn an_empty_topic_is_rejected() {
        let mut c = cfg("https://ntfy.sh".into());
        c.topic = "  ".into();
        assert!(NtfyNotifier::new("push", &c, crate::sources::http_client().unwrap()).is_err());
    }
}
