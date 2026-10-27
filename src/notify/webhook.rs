//! Generic JSON webhook, with an optional HMAC-SHA256 body signature.

use super::{NotifyError, Notifier};
use crate::config::{channel::WebhookConfig, secret};
use crate::pipeline::Alert;
use anyhow::{Context, Result};
use async_trait::async_trait;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use secrecy::{ExposeSecret, SecretString};
use sha2::Sha256;

pub const SIGNATURE_HEADER: &str = "x-vedette-signature";

pub struct WebhookNotifier {
    name: String,
    http: reqwest::Client,
    url: String,
    headers: HeaderMap,
    hmac_secret: Option<SecretString>,
}

impl WebhookNotifier {
    pub fn new(name: &str, cfg: &WebhookConfig, http: reqwest::Client) -> Result<Self> {
        let mut headers = HeaderMap::new();
        for (k, v) in &cfg.headers {
            headers.insert(
                HeaderName::from_bytes(k.as_bytes())
                    .with_context(|| format!("`{k}` is not a valid header name"))?,
                HeaderValue::from_str(v)
                    .with_context(|| format!("header `{k}` has an invalid value"))?,
            );
        }
        Ok(Self {
            name: name.to_string(),
            http,
            url: cfg.url.clone(),
            headers,
            hmac_secret: secret::pick(
                "hmac_secret",
                cfg.hmac_secret.as_ref(),
                cfg.hmac_secret_file.as_ref(),
            )?,
        })
    }

    fn body(&self, batch: &[Alert]) -> Result<String> {
        Ok(serde_json::to_string(&serde_json::json!({
            "source": "vedette",
            "version": env!("CARGO_PKG_VERSION"),
            "count": batch.len(),
            "alerts": batch,
        }))?)
    }

    /// `sha256=<hex>` over the exact bytes sent, so a receiver can verify integrity.
    pub fn sign(secret: &str, body: &str) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
            .expect("HMAC accepts a key of any length");
        mac.update(body.as_bytes());
        format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    }
}

#[async_trait]
impl Notifier for WebhookNotifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "webhook"
    }

    async fn send(&self, batch: &[Alert]) -> Result<(), NotifyError> {
        if batch.is_empty() {
            return Ok(());
        }
        let body = self.body(batch).map_err(NotifyError::Permanent)?;
        let mut req = self
            .http
            .post(&self.url)
            .headers(self.headers.clone())
            .header(reqwest::header::CONTENT_TYPE, "application/json");
        if let Some(s) = &self.hmac_secret {
            req = req.header(SIGNATURE_HEADER, Self::sign(s.expose_secret(), &body));
        }

        let resp = req.body(body).send().await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(NotifyError::from_status(status, text));
        }
        tracing::info!(channel = %self.name, items = batch.len(), "webhook delivered");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Secret;
    use crate::events::EventKind;
    use crate::notify::render::tests::alert;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cfg(url: String) -> WebhookConfig {
        WebhookConfig {
            url,
            headers: Default::default(),
            hmac_secret: None,
            hmac_secret_file: None,
        }
    }

    fn batch() -> Vec<Alert> {
        vec![alert("CVE-2026-1", "nginx", EventKind::KevAdded, Some("CRITICAL"))]
    }

    #[tokio::test]
    async fn posts_the_alerts_as_json() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let n = WebhookNotifier::new(
            "siem",
            &cfg(format!("{}/hook", server.uri())),
            crate::sources::http_client().unwrap(),
        )
        .unwrap();
        n.send(&batch()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&reqs[0].body).unwrap();
        assert_eq!(body["source"], "vedette");
        assert_eq!(body["count"], 1);
        assert_eq!(body["alerts"][0]["cve_id"], "CVE-2026-1");
        assert_eq!(body["alerts"][0]["in_kev"], true);
    }

    #[tokio::test]
    async fn custom_headers_are_sent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(header_exists("x-source"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let mut c = cfg(format!("{}/hook", server.uri()));
        c.headers.insert("X-Source".into(), "vedette".into());
        let n = WebhookNotifier::new("siem", &c, crate::sources::http_client().unwrap()).unwrap();
        n.send(&batch()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(
            reqs[0].headers.get("x-source").and_then(|v| v.to_str().ok()),
            Some("vedette")
        );
    }

    #[tokio::test]
    async fn the_signature_covers_the_exact_bytes_sent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let mut c = cfg(format!("{}/hook", server.uri()));
        c.hmac_secret = Some(Secret::Interpolated("topsecret".into()));
        let n = WebhookNotifier::new("siem", &c, crate::sources::http_client().unwrap()).unwrap();
        n.send(&batch()).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let sig = reqs[0]
            .headers
            .get(SIGNATURE_HEADER)
            .and_then(|v| v.to_str().ok())
            .unwrap();
        let body = String::from_utf8(reqs[0].body.clone()).unwrap();
        assert_eq!(sig, WebhookNotifier::sign("topsecret", &body));
        assert!(sig.starts_with("sha256="));
    }

    #[tokio::test]
    async fn no_signature_header_without_a_secret() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let n = WebhookNotifier::new(
            "siem",
            &cfg(format!("{}/hook", server.uri())),
            crate::sources::http_client().unwrap(),
        )
        .unwrap();
        n.send(&batch()).await.unwrap();
        let reqs = server.received_requests().await.unwrap();
        assert!(reqs[0].headers.get(SIGNATURE_HEADER).is_none());
    }

    #[tokio::test]
    async fn a_500_is_retryable_and_a_400_is_not() {
        for (status, retryable) in [(500u16, true), (400u16, false)] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;
            let n = WebhookNotifier::new(
                "siem",
                &cfg(format!("{}/hook", server.uri())),
                crate::sources::http_client().unwrap(),
            )
            .unwrap();
            let err = n.send(&batch()).await.unwrap_err();
            assert_eq!(err.is_retryable(), retryable, "status {status}");
        }
    }

    #[test]
    fn an_invalid_header_name_fails_at_construction() {
        let mut c = cfg("https://example.test/hook".into());
        c.headers.insert("bad header".into(), "x".into());
        assert!(
            WebhookNotifier::new("siem", &c, crate::sources::http_client().unwrap()).is_err()
        );
    }
}
