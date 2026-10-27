//! Development channel: appends each batch to a local file instead of sending it.
//!
//! Useful for working on watches or templates without a mail sink or push server, and
//! for `tail -f` while the daemon runs. Not meant for production alerting: nothing reads
//! the file, so an alert written here is an alert nobody sees.

use super::{render, Notifier, NotifyError};
use crate::config::channel::{FileConfig, FileFormat};
use crate::pipeline::Alert;
use anyhow::Result;
use async_trait::async_trait;
use std::io::Write;
use std::path::PathBuf;

pub struct FileNotifier {
    name: String,
    path: PathBuf,
    format: FileFormat,
}

impl FileNotifier {
    pub fn new(name: &str, cfg: &FileConfig) -> Result<Self> {
        if cfg.path.as_os_str().is_empty() {
            anyhow::bail!("file channel requires a non-empty `path`");
        }
        Ok(Self {
            name: name.to_string(),
            path: cfg.path.clone(),
            format: cfg.format,
        })
    }

    /// Everything one batch appends, built up front so it goes out in a single write.
    fn entry(&self, batch: &[Alert]) -> Result<String> {
        let now = jiff::Timestamp::now()
            .strftime("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        match self.format {
            FileFormat::Text => Ok(format!(
                "----- {now} channel={} items={}\n{}\n\n",
                self.name,
                batch.len(),
                render::text(batch)?.trim_end()
            )),
            FileFormat::Jsonl => {
                let mut out = String::new();
                for a in batch {
                    out.push_str(&serde_json::to_string(&serde_json::json!({
                        "ts": now,
                        "channel": self.name,
                        "alert": a,
                    }))?);
                    out.push('\n');
                }
                Ok(out)
            }
        }
    }

    fn append(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?
            .write_all(data)
    }
}

#[async_trait]
impl Notifier for FileNotifier {
    fn name(&self) -> &str {
        &self.name
    }
    fn kind(&self) -> &'static str {
        "file"
    }

    async fn send(&self, batch: &[Alert]) -> Result<(), NotifyError> {
        if batch.is_empty() {
            return Ok(());
        }
        let data = self.entry(batch).map_err(NotifyError::Permanent)?;
        let path = self.path.clone();
        let res = tokio::task::spawn_blocking(move || Self::append(&path, data.as_bytes()))
            .await
            .map_err(|e| NotifyError::Retryable(e.into()))?;
        if let Err(e) = res {
            use std::io::ErrorKind::*;
            // A path that cannot be written without a config change is not worth retrying.
            let permanent = matches!(
                e.kind(),
                PermissionDenied | IsADirectory | ReadOnlyFilesystem
            );
            let e = anyhow::Error::new(e).context(format!("appending to {}", self.path.display()));
            return Err(if permanent {
                NotifyError::Permanent(e)
            } else {
                NotifyError::Retryable(e)
            });
        }
        tracing::info!(channel = %self.name, items = batch.len(), path = %self.path.display(), "written to file");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventKind;
    use crate::notify::render::tests::alert;

    fn notifier(path: PathBuf, format: FileFormat) -> FileNotifier {
        FileNotifier::new("dev-log", &FileConfig { path, format }).unwrap()
    }

    #[tokio::test]
    async fn text_batches_append_with_a_header_each() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/alerts.log");
        let n = notifier(path.clone(), FileFormat::Text);

        n.send(&[alert("CVE-2026-1", "nginx", EventKind::New, Some("HIGH"))])
            .await
            .unwrap();
        n.send(&[alert(
            "CVE-2026-2",
            "nginx",
            EventKind::KevAdded,
            Some("CRITICAL"),
        )])
        .await
        .unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        assert_eq!(out.matches("----- ").count(), 2, "{out}");
        assert!(out.contains("channel=dev-log items=1"), "{out}");
        assert!(
            out.contains("CVE-2026-1") && out.contains("CVE-2026-2"),
            "{out}"
        );
        assert!(out.contains("actively exploited"), "{out}");
    }

    #[tokio::test]
    async fn jsonl_writes_one_parseable_line_per_alert() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("alerts.jsonl");
        let n = notifier(path.clone(), FileFormat::Jsonl);

        n.send(&[
            alert("CVE-2026-1", "nginx", EventKind::New, Some("HIGH")),
            alert("CVE-2026-2", "wordpress", EventKind::KevAdded, None),
        ])
        .await
        .unwrap();

        let out = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<serde_json::Value> = out
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0]["channel"], "dev-log");
        assert_eq!(lines[1]["alert"]["cve_id"], "CVE-2026-2");
        assert_eq!(lines[1]["alert"]["in_kev"], true);
    }

    #[tokio::test]
    async fn an_unwritable_path_is_a_permanent_failure() {
        let dir = tempfile::tempdir().unwrap();
        // The path is an existing directory, which can never be opened for append.
        let n = notifier(dir.path().to_path_buf(), FileFormat::Text);
        let err = n
            .send(&[alert("CVE-2026-1", "nginx", EventKind::New, Some("HIGH"))])
            .await
            .unwrap_err();
        assert!(!err.is_retryable(), "{err}");
    }

    #[test]
    fn parses_from_channel_config() {
        let c: crate::config::ChannelConfig = toml::from_str(
            r#"
            name = "dev-log"
            kind = "file"
            path = "data/alerts.jsonl"
            format = "jsonl"
            "#,
        )
        .unwrap();
        assert_eq!(c.kind_name(), "file");
        match c.kind {
            crate::config::ChannelKind::File(f) => assert_eq!(f.format, FileFormat::Jsonl),
            _ => unreachable!(),
        }
    }
}
