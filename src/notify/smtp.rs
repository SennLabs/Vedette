//! SMTP email, as a multipart HTML + plain-text digest.

use super::{render, NotifyError, Notifier};
use crate::config::{channel::SmtpConfig, channel::SmtpTls, secret};
use crate::pipeline::Alert;
use anyhow::{Context, Result};
use async_trait::async_trait;
use lettre::message::{header::ContentType, Mailbox, MultiPart, SinglePart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use secrecy::ExposeSecret;

pub struct SmtpNotifier {
    name: String,
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: Mailbox,
    to: Vec<Mailbox>,
}

impl SmtpNotifier {
    pub fn new(name: &str, cfg: &SmtpConfig) -> Result<Self> {
        let from: Mailbox = cfg
            .from
            .parse()
            .with_context(|| format!("`from` address `{}` is not a valid mailbox", cfg.from))?;
        if cfg.to.is_empty() {
            anyhow::bail!("`to` must list at least one recipient");
        }
        let to: Vec<Mailbox> = cfg
            .to
            .iter()
            .map(|a| {
                a.parse::<Mailbox>()
                    .with_context(|| format!("recipient `{a}` is not a valid mailbox"))
            })
            .collect::<Result<_>>()?;

        let mut builder = match cfg.tls {
            // STARTTLS: refuses to proceed if the server does not offer the upgrade,
            // rather than silently falling back to plaintext.
            SmtpTls::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&cfg.host)
                .with_context(|| format!("configuring STARTTLS for {}", cfg.host))?,
            SmtpTls::Implicit => AsyncSmtpTransport::<Tokio1Executor>::relay(&cfg.host)
                .with_context(|| format!("configuring implicit TLS for {}", cfg.host))?,
            SmtpTls::None => {
                tracing::warn!(
                    channel = name,
                    host = %cfg.host,
                    "SMTP channel is unencrypted; only appropriate for a local sink"
                );
                AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&cfg.host)
            }
        }
        .port(cfg.port);

        let password = secret::pick("password", cfg.password.as_ref(), cfg.password_file.as_ref())?;
        match (&cfg.username, password) {
            (Some(u), Some(p)) => {
                builder = builder.credentials(Credentials::new(
                    u.clone(),
                    p.expose_secret().to_string(),
                ));
            }
            (Some(_), None) => {
                anyhow::bail!("`username` is set but no `password` or `password_file` was given")
            }
            (None, Some(_)) => anyhow::bail!("a password was given but `username` is not set"),
            (None, None) => {}
        }

        Ok(Self {
            name: name.to_string(),
            transport: builder.build(),
            from,
            to,
        })
    }

    fn build_message(&self, batch: &[Alert]) -> Result<Message> {
        let subject = render::heading(batch);
        let mut builder = Message::builder().from(self.from.clone()).subject(subject);
        for t in &self.to {
            builder = builder.to(t.clone());
        }
        // Both parts, so a text-only client still gets something readable.
        Ok(builder.multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(render::text(batch)?),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(render::html(batch)?),
                ),
        )?)
    }
}

#[async_trait]
impl Notifier for SmtpNotifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "smtp"
    }

    async fn send(&self, batch: &[Alert]) -> Result<(), NotifyError> {
        if batch.is_empty() {
            return Ok(());
        }
        let msg = self
            .build_message(batch)
            // A message that cannot even be assembled will never assemble; do not retry.
            .map_err(NotifyError::Permanent)?;
        self.transport.send(msg).await.map_err(|e| {
            // lettre distinguishes a permanent 5xx rejection from a transient 4xx or a
            // transport failure, which maps exactly onto the outbox's two cases.
            if e.is_permanent() {
                NotifyError::Permanent(anyhow::Error::new(e).context("SMTP rejected the message"))
            } else {
                NotifyError::Retryable(anyhow::Error::new(e).context("SMTP delivery failed"))
            }
        })?;
        tracing::info!(channel = %self.name, items = batch.len(), "email sent");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every test is async: lettre's transport needs a tokio runtime in scope even to
    // be dropped, so a plain #[test] aborts during cleanup.
    use crate::config::Secret;

    fn cfg() -> SmtpConfig {
        SmtpConfig {
            host: "localhost".into(),
            port: 1025,
            tls: SmtpTls::None,
            username: None,
            password: None,
            password_file: None,
            from: "Vedette <alerts@example.com>".into(),
            to: vec!["ops@example.com".into()],
        }
    }

    #[tokio::test]
    async fn builds_a_multipart_message_with_both_parts() {
        let n = SmtpNotifier::new("mail", &cfg()).unwrap();
        let batch = vec![super::super::render::tests::alert(
            "CVE-2026-1",
            "nginx",
            crate::events::EventKind::KevAdded,
            Some("CRITICAL"),
        )];
        let msg = n.build_message(&batch).unwrap();
        let raw = String::from_utf8_lossy(&msg.formatted()).to_string();
        assert!(raw.contains("multipart/alternative"));
        assert!(raw.contains("text/plain"));
        assert!(raw.contains("text/html"));
        assert!(raw.contains("[KEV]"), "the subject must lead with KEV");
    }

    #[tokio::test]
    async fn rejects_a_malformed_from_address() {
        let mut c = cfg();
        c.from = "not an address".into();
        assert!(SmtpNotifier::new("mail", &c).is_err());
    }

    #[tokio::test]
    async fn rejects_an_empty_recipient_list() {
        let mut c = cfg();
        c.to = vec![];
        let err = SmtpNotifier::new("mail", &c).err().unwrap().to_string();
        assert!(err.contains("at least one recipient"), "{err}");
    }

    #[tokio::test]
    async fn a_username_without_a_password_is_a_config_error() {
        let mut c = cfg();
        c.username = Some("alerts".into());
        let err = SmtpNotifier::new("mail", &c).err().unwrap().to_string();
        assert!(err.contains("no `password`"), "{err}");
    }

    #[tokio::test]
    async fn a_password_without_a_username_is_a_config_error() {
        let mut c = cfg();
        c.password = Some(Secret::Interpolated("hunter2".into()));
        let err = SmtpNotifier::new("mail", &c).err().unwrap().to_string();
        assert!(err.contains("`username` is not set"), "{err}");
    }

    #[tokio::test]
    async fn multiple_recipients_all_land_on_the_message() {
        let mut c = cfg();
        c.to = vec!["a@example.com".into(), "b@example.com".into()];
        let n = SmtpNotifier::new("mail", &c).unwrap();
        let batch = vec![super::super::render::tests::alert(
            "CVE-2026-1",
            "nginx",
            crate::events::EventKind::New,
            Some("HIGH"),
        )];
        let raw = String::from_utf8_lossy(&n.build_message(&batch).unwrap().formatted()).to_string();
        assert!(raw.contains("a@example.com") && raw.contains("b@example.com"));
    }
}
