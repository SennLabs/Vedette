//! Configuration loading. `vedette.toml` holds daemon settings and channels;
//! `watches.toml` holds the watch list. Both are committed; neither holds a secret.

pub mod channel;
pub mod secret;
pub mod watch;

pub use channel::{ChannelConfig, ChannelKind};
pub use secret::Secret;
pub use watch::{CpeSelector, Field, Keywords, Severity, Watch, WatchFile};

use anyhow::{anyhow, Context, Result};
use figment::{
    providers::{Env, Format, Serialized, Toml},
    Figment,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// NVD's hard cap is 120 days per `lastModStartDate`/`lastModEndDate` window, and a
/// wider span answers with a bare 404. 110 leaves room for clock skew.
pub const NVD_MAX_WINDOW_DAYS: i64 = 110;

/// NVD answers a `lastModified` span wider than 120 days with a bare 404, so the
/// configured window must stay strictly under that. Enforced at compile time.
const _: () = assert!(NVD_MAX_WINDOW_DAYS < 120);

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NvdSettings {
    pub base_url: String,
    #[serde(default, skip_serializing)]
    pub api_key: Option<Secret>,
    #[serde(default, skip_serializing)]
    pub api_key_file: Option<PathBuf>,
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
    /// How far back a cold-start sync reaches by `lastModified`: a lookback like `90d`,
    /// or a `YYYY-MM-DD` date.
    pub backfill_from: String,
    /// Requests allowed per `rate_window`. NVD documents 50/30s with a key, 5/30s without;
    /// the default leaves headroom so a retry burst cannot trip the limit.
    pub rate_limit: u32,
    #[serde(with = "humantime_serde")]
    pub rate_window: Duration,
    /// CVEs per request. NVD allows up to 2000, but a 2000-result page takes minutes to
    /// stream and loses all its work if the connection drops, so the default is smaller:
    /// more requests, each quick and individually retryable.
    pub page_size: u32,
    /// Re-fetch this far behind the stored watermark; absorbs NVD's eventual consistency.
    #[serde(with = "humantime_serde")]
    pub overlap: Duration,
    /// Idle time allowed between reads before a request is considered stalled.
    #[serde(with = "humantime_serde")]
    pub read_timeout: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct KevSettings {
    pub url: String,
    #[serde(with = "humantime_serde")]
    pub poll_interval: Duration,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotifySettings {
    pub max_attempts: u32,
    #[serde(with = "humantime_serde")]
    pub retry_base: Duration,
    /// Items in one digest before it is split; keeps a mail body readable.
    pub max_batch: usize,
    /// When true, no channel actually sends — the outbox is marked `sent` with a log line.
    /// Useful for a first run against a large backfill.
    pub dry_run: bool,
}

/// Deliberately without `deny_unknown_fields`: the `VEDETTE_` environment provider feeds
/// every variable with that prefix into the top level, and `VEDETTE_CONFIG`, `VEDETTE_LOG`
/// and the compose file's `VEDETTE_VERSION` are not settings. The nested structs do deny
/// unknown fields, so a typo inside `[nvd]`, `[kev]`, `[notify]` or a channel is an error.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Settings {
    pub database_path: PathBuf,
    pub watch_file: PathBuf,
    /// `healthcheck` fails when a source has not synced successfully within this long.
    #[serde(with = "humantime_serde")]
    pub stale_after: Duration,
    pub nvd: NvdSettings,
    pub kev: KevSettings,
    pub notify: NotifySettings,
    #[serde(default, skip_serializing)]
    pub channel: Vec<ChannelConfig>,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            database_path: PathBuf::from("data/vedette.db"),
            watch_file: PathBuf::from("config/watches.toml"),
            stale_after: Duration::from_secs(6 * 3600),
            nvd: NvdSettings {
                base_url: "https://services.nvd.nist.gov/rest/json".into(),
                api_key: None,
                api_key_file: None,
                poll_interval: Duration::from_secs(30 * 60),
                backfill_from: "90d".into(),
                rate_limit: 45,
                rate_window: Duration::from_secs(30),
                page_size: 500,
                overlap: Duration::from_secs(600),
                read_timeout: Duration::from_secs(90),
            },
            kev: KevSettings {
                url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json".into(),
                poll_interval: Duration::from_secs(3600),
            },
            notify: NotifySettings {
                max_attempts: 6,
                retry_base: Duration::from_secs(30),
                max_batch: 50,
                dry_run: false,
            },
            channel: Vec::new(),
        }
    }
}

impl Settings {
    /// Precedence: built-in defaults -> `vedette.toml` -> `VEDETTE_*` environment.
    pub fn load(config_path: Option<&Path>) -> Result<Self> {
        let mut fig = Figment::from(Serialized::defaults(Settings::default()));
        if let Some(p) = config_path {
            if !p.exists() {
                return Err(anyhow!("config file {} does not exist", p.display()));
            }
            fig = fig.merge(Toml::file(p));
        } else if Path::new("config/vedette.toml").exists() {
            fig = fig.merge(Toml::file("config/vedette.toml"));
        }
        // VEDETTE_NVD__POLL_INTERVAL=15m reaches nvd.poll_interval.
        let settings: Settings = fig
            .merge(Env::prefixed("VEDETTE_").split("__"))
            .extract()
            .context("loading configuration")?;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for c in &self.channel {
            if !seen.insert(c.name.as_str()) {
                return Err(anyhow!("duplicate channel name `{}`", c.name));
            }
        }
        if self.nvd.page_size == 0 || self.nvd.page_size > 2000 {
            return Err(anyhow!("nvd.page_size must be between 1 and 2000"));
        }
        if self.nvd.rate_limit == 0 {
            return Err(anyhow!("nvd.rate_limit must be at least 1"));
        }
        Ok(())
    }

    pub fn nvd_api_key(&self) -> Result<Option<secrecy::SecretString>> {
        // The env var is the path of least resistance for `docker run -e`.
        if let Ok(k) = std::env::var("NVD_API_KEY") {
            if !k.trim().is_empty() {
                return Ok(Some(secrecy::SecretString::from(k.trim().to_string())));
            }
        }
        secret::pick(
            "nvd.api_key",
            self.nvd.api_key.as_ref(),
            self.nvd.api_key_file.as_ref(),
        )
    }

    pub fn channel_by_name(&self, name: &str) -> Option<&ChannelConfig> {
        self.channel.iter().find(|c| c.name == name)
    }

    /// Resolves a watch's `channels` list, defaulting to every enabled channel. A channel
    /// that is named but disabled is skipped: the dispatcher never builds it, so queueing
    /// for it would only park rows until someone re-enabled it and got the backlog.
    pub fn channels_for(&self, declared: &[String]) -> Result<Vec<&ChannelConfig>> {
        if declared.is_empty() {
            return Ok(self.channel.iter().filter(|c| c.enabled).collect());
        }
        let named = declared
            .iter()
            .map(|n| {
                self.channel_by_name(n)
                    .ok_or_else(|| anyhow!("watch references unknown channel `{n}`"))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(named.into_iter().filter(|c| c.enabled).collect())
    }

    pub fn load_watches(&self) -> Result<WatchFile> {
        WatchFile::load(&self.watch_file)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_valid() {
        // The window cap is asserted at compile time; `windows()` is covered in timeutil
        // and the keyless rate clamp in sources::nvd.
        Settings::default().validate().unwrap();
    }

    #[test]
    fn the_default_page_size_is_small_enough_to_stream_reliably() {
        // A 2000-result NVD page measured 7.2 MB over 143 s on a live request. The whole
        // page is lost if the connection drops, so the default trades more requests for
        // individually retryable ones.
        let s = Settings::default();
        assert!(s.nvd.page_size <= 500, "got {}", s.nvd.page_size);
        assert!(s.nvd.page_size > 0);
    }

    #[test]
    fn channel_toml_round_trips() {
        let toml_src = r#"
            database_path = "x.db"
            [[channel]]
            name = "secops-email"
            kind = "smtp"
            host = "localhost"
            port = 1025
            tls = "none"
            from = "a@b.c"
            to = ["d@e.f"]
            [[channel]]
            name = "push"
            kind = "ntfy"
            topic = "vedette"
        "#;
        let s: Settings = Figment::from(Serialized::defaults(Settings::default()))
            .merge(Toml::string(toml_src))
            .extract()
            .unwrap();
        s.validate().unwrap();
        assert_eq!(s.channel.len(), 2);
        assert_eq!(s.channel[0].kind_name(), "smtp");
        assert_eq!(s.channel[1].kind_name(), "ntfy");
        assert_eq!(s.database_path, PathBuf::from("x.db"));
    }

    #[test]
    fn unknown_channel_reference_is_an_error() {
        let s = Settings::default();
        assert!(s.channels_for(&["nope".to_string()]).is_err());
    }
}
