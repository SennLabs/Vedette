//! The daemon loop: poll both sources on their own intervals, match, and drain the outbox.
//!
//! The watch file is re-read whenever there is something to match and on SIGHUP, so
//! adding a watch needs no restart. When a watch's matching definition changes, the
//! stored corpus is re-evaluated against it, which is how a new watch surfaces CVEs
//! already in the database without a fresh backfill.

use crate::config::{Settings, Watch};
use crate::db::{queries, Db};
use crate::notify::Notifier;
use crate::pipeline::Enqueue;
use crate::sources::model::CveSnapshot;
use crate::{outbox, pipeline, sources};
use anyhow::{Context, Result};
use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::signal::unix::{Signal, SignalKind};

/// How often the outbox is drained. Independent of the poll intervals so a batch window
/// that elapses between polls still goes out promptly.
const DRAIN_INTERVAL: Duration = Duration::from_secs(60);

/// Cap on how much of the stored corpus is re-evaluated when a watch definition changes.
/// Without a cap, editing a watch on a database holding years of CVEs would stall the
/// daemon for minutes on its next cycle.
const REEVALUATE_LIMIT: usize = 20_000;

/// CVEs loaded per pipeline pass, so a large sync never holds one huge candidate set.
const CHUNK: usize = 2_000;

pub struct Daemon {
    db: Db,
    settings: Settings,
    notifiers: BTreeMap<String, Arc<dyn Notifier>>,
    /// The last watch list that parsed. A broken edit must not stop matching: the CVEs
    /// fetched while the file is unparseable would otherwise be stored unmatched and
    /// never alert.
    last_good_watches: Mutex<Option<Vec<Watch>>>,
}

/// The two signals that stop the daemon, polled together so a cycle can be cancelled.
struct Shutdown {
    sigterm: Signal,
    sigint: Signal,
}

impl Shutdown {
    fn install() -> Result<Self> {
        Ok(Self {
            sigterm: unix_signal(SignalKind::terminate())?,
            sigint: unix_signal(SignalKind::interrupt())?,
        })
    }

    async fn recv(&mut self) -> &'static str {
        tokio::select! {
            _ = self.sigterm.recv() => "SIGTERM",
            _ = self.sigint.recv() => "SIGINT",
        }
    }

    /// Runs `work` unless a stop signal arrives first, in which case the work is dropped
    /// mid-flight. That is safe: every NVD window and KEV catalog is committed as a unit,
    /// so an abandoned fetch is simply redone next start. Without this, `docker stop`
    /// during the first sync could only ever end in SIGKILL.
    async fn guard<T>(&mut self, work: impl std::future::Future<Output = T>) -> Option<T> {
        tokio::select! {
            out = work => Some(out),
            name = self.recv() => {
                tracing::info!(signal = name, "stop requested; abandoning the current cycle");
                None
            }
        }
    }
}

impl Daemon {
    pub fn new(db: Db, settings: Settings) -> Result<Self> {
        let notifiers =
            crate::notify::build_for(&settings).context("building notification channels")?;
        if notifiers.is_empty() {
            tracing::warn!("no enabled notification channels: matches will be stored only");
        }
        Ok(Self {
            db,
            settings,
            notifiers,
            last_good_watches: Mutex::new(None),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let http = sources::http_client_with(self.settings.nvd.read_timeout)?;
        let nvd = sources::nvd::NvdClient::new(
            http.clone(),
            &self.settings.nvd,
            self.settings.nvd_api_key()?,
        )?;
        let kev = sources::kev::KevClient::new(http, &self.settings.kev.url);

        // Fire every source once at startup rather than waiting out a full interval.
        let mut nvd_tick = tokio::time::interval(self.settings.nvd.poll_interval);
        let mut kev_tick = tokio::time::interval(self.settings.kev.poll_interval);
        let mut drain_tick = tokio::time::interval(DRAIN_INTERVAL);
        for t in [&mut nvd_tick, &mut kev_tick, &mut drain_tick] {
            // Skip missed ticks instead of firing a burst after the process was suspended.
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        }

        let mut sighup = unix_signal(SignalKind::hangup())?;
        let mut stop = Shutdown::install()?;

        tracing::info!(
            nvd_interval = ?self.settings.nvd.poll_interval,
            kev_interval = ?self.settings.kev.poll_interval,
            channels = self.notifiers.len(),
            "vedette daemon started"
        );

        loop {
            tokio::select! {
                _ = kev_tick.tick() => {
                    match stop.guard(self.cycle_kev(&kev)).await {
                        None => break,
                        // A failed poll must never take the daemon down; the next tick retries.
                        Some(Err(e)) => tracing::error!(error = %format!("{e:#}"), "KEV cycle failed"),
                        Some(Ok(())) => {}
                    }
                }
                _ = nvd_tick.tick() => {
                    match stop.guard(self.cycle_nvd(&nvd)).await {
                        None => break,
                        Some(Err(e)) => tracing::error!(error = %format!("{e:#}"), "NVD cycle failed"),
                        Some(Ok(())) => {}
                    }
                }
                _ = drain_tick.tick() => {
                    match outbox::drain(&self.db, &self.settings, &self.notifiers, false).await {
                        Ok(s) if s.sent > 0 || s.failed > 0 => {
                            tracing::info!(sent = s.sent, retried = s.retried, failed = s.failed,
                                           held = s.held, "outbox drained");
                        }
                        Ok(_) => {}
                        Err(e) => tracing::error!(error = %format!("{e:#}"), "outbox drain failed"),
                    }
                }
                _ = sighup.recv() => {
                    tracing::info!("SIGHUP: reloading the watch file");
                    match self.reload().await {
                        Ok(n) if n > 0 => tracing::info!(changed = n, "watch definitions changed"),
                        Ok(_) => tracing::info!("watch file reloaded, no definitions changed"),
                        Err(e) => tracing::error!(error = %format!("{e:#}"),
                                                  "reload failed; keeping the previous watches"),
                    }
                }
                name = stop.recv() => {
                    tracing::info!(signal = name, "shutting down");
                    break;
                }
            }
        }

        // One last drain so anything already queued is not stranded until the next start.
        if let Err(e) = outbox::drain(&self.db, &self.settings, &self.notifiers, false).await {
            tracing::warn!(error = %format!("{e:#}"), "final outbox drain failed");
        }
        tracing::info!("vedette daemon stopped");
        Ok(())
    }

    /// The current watch list, falling back to the last one that parsed.
    fn watches(&self) -> Result<Vec<Watch>> {
        let mut cache = self
            .last_good_watches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match self.settings.load_watches() {
            Ok(file) => {
                *cache = Some(file.watches.clone());
                Ok(file.watches)
            }
            Err(e) => match cache.as_ref() {
                Some(previous) => {
                    tracing::error!(
                        error = %format!("{e:#}"),
                        "watch file does not parse; matching with the previous watches"
                    );
                    Ok(previous.clone())
                }
                None => Err(e),
            },
        }
    }

    /// Re-reads the watch file and re-evaluates the corpus for any watch whose matching
    /// definition changed. Returns how many changed.
    async fn reload(&self) -> Result<usize> {
        let watches = self.settings.load_watches()?.watches;
        *self
            .last_good_watches
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(watches.clone());
        let changed = pipeline::reconcile_watches(&self.db, &watches).await?;
        self.reevaluate(&watches, &changed, Enqueue::Live).await?;
        Ok(changed.len())
    }

    /// Re-evaluates the stored corpus against the watches named in `changed`, pruning
    /// matches they no longer produce. A no-op when nothing changed.
    async fn reevaluate(&self, watches: &[Watch], changed: &[String], mode: Enqueue) -> Result<()> {
        if changed.is_empty() {
            return Ok(());
        }
        let affected: Vec<_> = watches
            .iter()
            .filter(|w| changed.contains(&w.name))
            .cloned()
            .collect();
        tracing::info!(
            watches = ?changed,
            "re-evaluating the stored corpus against changed watches"
        );
        // "1970" simply means "everything stored", bounded by REEVALUATE_LIMIT.
        let ids = self
            .db
            .call(|c| queries::cve_ids_published_since(c, "1970-01-01T00:00:00.000", REEVALUATE_LIMIT))
            .await?;
        let candidates = self
            .db
            .call(move |c| queries::load_candidates(c, &ids))
            .await?;
        // A tightened watch must stop reporting what it no longer matches.
        let pruned = pipeline::prune_stale_matches(&self.db, &affected, &candidates).await?;
        let out = pipeline::process(
            &self.db,
            &self.settings,
            &affected,
            candidates,
            &HashMap::new(),
            mode,
        )
        .await?;
        tracing::info!(
            matched = out.matched,
            new_matches = out.new_matches,
            enqueued = out.enqueued,
            suppressed = out.suppressed,
            pruned,
            "corpus re-evaluation complete"
        );
        Ok(())
    }

    async fn cycle_kev(&self, client: &sources::kev::KevClient) -> Result<()> {
        let out = sources::kev::sync(&self.db, client, false).await?;
        if out.not_modified || out.newly_added.is_empty() {
            return Ok(());
        }
        if out.baseline {
            // The whole catalog is "new" on the first fetch; it is history, not news.
            tracing::info!(
                entries = out.newly_added.len(),
                "KEV baseline: recording matches without alerting"
            );
            return self.process_ids(out.newly_added, &HashMap::new(), Enqueue::Suppressed).await;
        }
        // A KEV addition is the most urgent signal available, so these are processed
        // immediately rather than waiting for the next NVD poll.
        self.process_ids(out.newly_added, &HashMap::new(), Enqueue::Live).await
    }

    async fn cycle_nvd(&self, client: &sources::nvd::NvdClient) -> Result<()> {
        let out = sources::nvd::sync(&self.db, client, &self.settings.nvd, None).await?;
        let mut snapshots: HashMap<String, (Option<CveSnapshot>, CveSnapshot)> = HashMap::new();
        let mut ids = Vec::with_capacity(out.deltas.len());
        for d in out.deltas {
            ids.push(d.id.clone());
            snapshots.insert(d.id, (d.old, d.new));
        }
        if out.baseline {
            // The first sync has reached the present. Record every stored CVE's matches
            // quietly, not just this run's deltas: a resumed baseline or an earlier
            // `backfill` may have stored CVEs that no pass has seen yet.
            let all = self.db.call(|c| queries::all_cve_ids(c)).await?;
            tracing::info!(cves = all.len(), "NVD baseline: recording matches without alerting");
            self.process_ids(all, &snapshots, Enqueue::Suppressed).await?;
            return sources::nvd::complete_baseline(&self.db).await;
        }
        if ids.is_empty() {
            return Ok(());
        }
        self.process_ids(ids, &snapshots, Enqueue::Live).await
    }

    async fn process_ids(
        &self,
        ids: Vec<String>,
        snapshots: &HashMap<String, (Option<CveSnapshot>, CveSnapshot)>,
        mode: Enqueue,
    ) -> Result<()> {
        let watches = self.watches()?;
        // Reconciling records the new definition hash, so a change seen here must be
        // acted on here; a later SIGHUP would find nothing left to do.
        let changed = pipeline::reconcile_watches(&self.db, &watches).await?;
        self.reevaluate(&watches, &changed, mode).await?;

        for chunk in ids.chunks(CHUNK) {
            let chunk = chunk.to_vec();
            let candidates = self
                .db
                .call(move |c| queries::load_candidates(c, &chunk))
                .await?;
            let out = pipeline::process(
                &self.db,
                &self.settings,
                &watches,
                candidates,
                snapshots,
                mode,
            )
            .await?;
            if out.matched > 0 {
                tracing::info!(
                    evaluated = out.evaluated,
                    matched = out.matched,
                    new_matches = out.new_matches,
                    enqueued = out.enqueued,
                    suppressed = out.suppressed,
                    "matched a batch"
                );
            }
        }
        Ok(())
    }
}

fn unix_signal(kind: SignalKind) -> Result<Signal> {
    tokio::signal::unix::signal(kind).context("registering a signal handler")
}

/// True when a source has not synced successfully within `stale_after`.
pub fn is_stale(last_success: Option<&str>, stale_after: Duration) -> bool {
    let Some(ts) = last_success else {
        return true;
    };
    match ts.parse::<jiff::Timestamp>() {
        Ok(t) => {
            let age = jiff::Timestamp::now().as_second().saturating_sub(t.as_second());
            age > stale_after.as_secs() as i64
        }
        // An unparseable watermark is itself a problem worth failing the healthcheck on.
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staleness_is_judged_against_the_window() {
        let fresh = jiff::Timestamp::now().to_string();
        assert!(!is_stale(Some(&fresh), Duration::from_secs(3600)));

        let old = jiff::Timestamp::now()
            .checked_sub(jiff::Span::new().hours(10))
            .unwrap()
            .to_string();
        assert!(is_stale(Some(&old), Duration::from_secs(3600)));

        // Never synced, or a corrupt watermark: both must fail the healthcheck.
        assert!(is_stale(None, Duration::from_secs(3600)));
        assert!(is_stale(Some("not-a-timestamp"), Duration::from_secs(3600)));
    }

    #[test]
    fn a_dry_run_daemon_substitutes_every_channel() {
        use figment::{
            providers::{Format, Serialized, Toml},
            Figment,
        };
        let settings: Settings = Figment::from(Serialized::defaults(Settings::default()))
            .merge(Toml::string(
                r#"
                [notify]
                dry_run = true
                max_attempts = 6
                retry_base = "30s"
                max_batch = 50
                [[channel]]
                name = "mail"
                kind = "smtp"
                host = "localhost"
                port = 1025
                tls = "none"
                from = "a@b.c"
                to = ["d@e.f"]
                "#,
            ))
            .extract()
            .unwrap();
        let d = Daemon::new(Db::open_in_memory().unwrap(), settings).unwrap();
        assert_eq!(d.notifiers.len(), 1);
        assert_eq!(d.notifiers["mail"].kind(), "dry-run");
    }

    /// One NVD page holding a single nginx CVE with the given score.
    fn nvd_page(score: f64, severity: &str, last_mod: &str) -> serde_json::Value {
        serde_json::json!({
            "resultsPerPage": 1, "startIndex": 0, "totalResults": 1,
            "format": "NVD_CVE", "version": "2.0",
            "vulnerabilities": [{"cve": {
                "id": "CVE-2026-0001",
                "published": "2026-10-01T00:00:00.000",
                "lastModified": last_mod,
                "vulnStatus": "Analyzed",
                "descriptions": [{"lang": "en", "value": "A flaw in nginx"}],
                "metrics": {"cvssMetricV31": [{"type": "Primary", "cvssData": {
                    "version": "3.1", "baseScore": score, "baseSeverity": severity,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }}]},
                "references": [],
                "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [
                    {"vulnerable": true, "criteria": "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*",
                     "matchCriteriaId": "x"}
                ]}]}]
            }}]
        })
    }

    #[tokio::test]
    async fn the_baseline_records_matches_and_alerts_only_on_later_changes() {
        use figment::{
            providers::{Format, Serialized, Toml},
            Figment,
        };
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let dir = tempfile::tempdir().unwrap();
        let watch_file = dir.path().join("watches.toml");
        std::fs::write(&watch_file, "[[watch]]\nname = \"nginx\"\ncpe = [\"f5:nginx\"]\n").unwrap();

        let server = MockServer::start().await;
        let mut settings: Settings = Figment::from(Serialized::defaults(Settings::default()))
            .merge(Toml::string(
                r#"
                [notify]
                dry_run = true
                max_attempts = 6
                retry_base = "30s"
                max_batch = 50
                [[channel]]
                name = "dev-log"
                kind = "file"
                path = "unused.log"
                "#,
            ))
            .extract()
            .unwrap();
        settings.watch_file = watch_file;
        settings.nvd.base_url = format!("{}/rest/json", server.uri());
        settings.nvd.backfill_from = "7d".into();
        settings.nvd.rate_limit = 1000;
        settings.nvd.rate_window = Duration::from_millis(1);
        let client = sources::nvd::NvdClient::new(
            sources::http_client().unwrap(),
            &settings.nvd,
            None,
        )
        .unwrap();
        let d = Daemon::new(Db::open_in_memory().unwrap(), settings).unwrap();
        let count = |sql: &'static str| {
            let db = d.db.clone();
            async move {
                db.call(move |c| Ok(c.query_row(sql, [], |r| r.get::<_, i64>(0))?))
                    .await
                    .unwrap()
            }
        };

        // First sync: the baseline. The match is recorded and its events are written as
        // suppressed, so nothing is deliverable and nothing can be queued for real later.
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_page(
                7.5,
                "HIGH",
                "2026-10-20T00:00:00.000",
            )))
            .mount(&server)
            .await;
        d.cycle_nvd(&client).await.unwrap();
        assert_eq!(count("SELECT COUNT(*) FROM matches").await, 1);
        assert_eq!(count("SELECT COUNT(*) FROM notifications WHERE state = 'pending'").await, 0);
        assert_eq!(count("SELECT COUNT(*) FROM notifications WHERE state = 'suppressed'").await, 1);

        // Second sync: live. The score rises, which alerts; the match itself is not "new"
        // again, because the baseline recorded it.
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(nvd_page(
                9.8,
                "CRITICAL",
                "2026-10-26T00:00:00.000",
            )))
            .mount(&server)
            .await;
        d.cycle_nvd(&client).await.unwrap();
        assert_eq!(
            count("SELECT COUNT(*) FROM notifications WHERE event_kind = 'score_increase' AND state = 'pending'").await,
            1
        );
        assert_eq!(
            count("SELECT COUNT(*) FROM notifications WHERE event_kind = 'new' AND state = 'pending'").await,
            0
        );

        // A re-evaluation after the baseline (what `vedette match` or a SIGHUP does)
        // finds the baseline's `new` slot already taken and announces nothing.
        let watches = d.settings.load_watches().unwrap().watches;
        let ids = d.db.call(|c| queries::all_cve_ids(c)).await.unwrap();
        let cands = d.db.call(move |c| queries::load_candidates(c, &ids)).await.unwrap();
        let out = pipeline::process(&d.db, &d.settings, &watches, cands, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();
        assert_eq!(out.enqueued, 0);
        assert_eq!(count("SELECT COUNT(*) FROM notifications WHERE state = 'pending'").await, 1);
    }
}
