//! The outbox dispatcher.
//!
//! Nothing in the pipeline ever sends a notification directly. Matches and their pending
//! notification rows are committed first, and this drains them afterwards. That split is
//! what makes a crash safe: delivery is at-least-once, and the
//! `UNIQUE(match_id, channel, event_fingerprint)` constraint collapses any repeat.
//!
//! Batching is the other half of being readable. A poll cycle that finds forty matches
//! must produce one digest, not forty emails — so rows are held until the channel's
//! `batch_window` elapses, unless something urgent arrives.

use crate::config::{ChannelConfig, Settings};
use crate::db::{queries, Db};
use crate::notify::Notifier;
use crate::pipeline::Alert;
use anyhow::{Context, Result};
use jiff::Timestamp;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug, Default, PartialEq)]
pub struct DrainStats {
    pub considered: usize,
    pub sent: usize,
    pub held: usize,
    pub retried: usize,
    pub failed: usize,
}

/// Backoff for a failed delivery: `retry_base * 2^attempts`, capped at an hour.
fn next_attempt(base: Duration, attempts: u32) -> Timestamp {
    let delay = base
        .saturating_mul(2u32.saturating_pow(attempts.min(16)))
        .min(Duration::from_secs(3600));
    Timestamp::now()
        .checked_add(jiff::Span::new().seconds(delay.as_secs().max(1) as i64))
        .unwrap_or_else(|_| Timestamp::now())
}

/// Whether this channel's pending rows should go out now, or wait for more company.
fn should_send(cfg: &ChannelConfig, rows: &[(queries::PendingRow, Alert)], force: bool) -> bool {
    if force || rows.is_empty() {
        return force;
    }
    if cfg.urgent_immediate && rows.iter().any(|(_, a)| a.urgent) {
        return true;
    }
    // A retry has already waited out its backoff; holding it again would compound the delay.
    if rows.iter().any(|(r, _)| r.attempts > 0) {
        return true;
    }
    if cfg.batch_window.is_zero() {
        return true;
    }
    let oldest = rows
        .iter()
        .filter_map(|(r, _)| r.created_at.parse::<Timestamp>().ok())
        .min();
    match oldest {
        Some(t) => {
            let age = Timestamp::now().as_second().saturating_sub(t.as_second());
            age >= cfg.batch_window.as_secs() as i64
        }
        // An unparseable timestamp must not strand an alert forever.
        None => true,
    }
}

/// Attempts delivery of everything currently due.
pub async fn drain(
    db: &Db,
    settings: &Settings,
    notifiers: &BTreeMap<String, Arc<dyn Notifier>>,
    force: bool,
) -> Result<DrainStats> {
    let mut stats = DrainStats::default();
    let now_ts = queries::now();

    for (name, notifier) in notifiers {
        let Some(cfg) = settings.channel_by_name(name) else {
            continue;
        };
        // Pull a generous slice so batching decisions see the real backlog.
        let fetch_limit = settings.notify.max_batch.saturating_mul(4).max(50);
        let (n, ts) = (name.clone(), now_ts.clone());
        let pending = db
            .call(move |c| queries::pending_for_channel(c, &n, &ts, fetch_limit))
            .await
            .with_context(|| format!("reading the outbox for channel `{name}`"))?;
        if pending.is_empty() {
            continue;
        }
        stats.considered += pending.len();

        // A row whose payload will not parse can never be delivered; retire it rather
        // than letting it block the channel forever.
        let mut rows: Vec<(queries::PendingRow, Alert)> = Vec::with_capacity(pending.len());
        let mut poisoned: Vec<i64> = Vec::new();
        for r in pending {
            match serde_json::from_str::<Alert>(&r.payload) {
                Ok(a) => rows.push((r, a)),
                Err(e) => {
                    tracing::error!(id = r.id, error = %e, "discarding an unparseable outbox row");
                    poisoned.push(r.id);
                }
            }
        }
        if !poisoned.is_empty() {
            let n = poisoned.len();
            db.call(move |c| {
                queries::mark_permanently_failed(c, &poisoned, "payload could not be parsed")
            })
            .await?;
            stats.failed += n;
        }

        if !should_send(cfg, &rows, force) {
            stats.held += rows.len();
            tracing::debug!(
                channel = %name,
                held = rows.len(),
                window_secs = cfg.batch_window.as_secs(),
                "holding alerts for the batch window"
            );
            continue;
        }

        for chunk in rows.chunks(settings.notify.max_batch.max(1)) {
            let ids: Vec<i64> = chunk.iter().map(|(r, _)| r.id).collect();
            let batch: Vec<Alert> = chunk.iter().map(|(_, a)| a.clone()).collect();
            let attempts = chunk.iter().map(|(r, _)| r.attempts).max().unwrap_or(0);

            match notifier.send(&batch).await {
                Ok(()) => {
                    let n = ids.len();
                    db.call(move |c| queries::mark_sent(c, &ids)).await?;
                    stats.sent += n;
                }
                Err(e) => {
                    let msg = format!("{e:#}");
                    let retryable = e.is_retryable();
                    let n = ids.len();
                    if retryable {
                        let next =
                            crate::timeutil::nvd_format(next_attempt(settings.notify.retry_base, attempts));
                        let max = settings.notify.max_attempts;
                        let (ids2, msg2, next2) = (ids, msg.clone(), next.clone());
                        let retired = db
                            .call(move |c| {
                                queries::mark_attempt_failed(c, &ids2, &msg2, &next2, max)
                            })
                            .await?;
                        stats.retried += n - retired;
                        stats.failed += retired;
                        tracing::warn!(
                            channel = %name,
                            items = n,
                            retired,
                            next_attempt = %next,
                            error = %msg,
                            "delivery failed; will retry"
                        );
                    } else {
                        let (ids2, msg2) = (ids, msg.clone());
                        db.call(move |c| queries::mark_permanently_failed(c, &ids2, &msg2))
                            .await?;
                        stats.failed += n;
                        tracing::error!(
                            channel = %name,
                            items = n,
                            error = %msg,
                            "delivery failed permanently; fix the channel config and run \
                             `vedette notify requeue`"
                        );
                    }
                    // Don't keep pushing into a channel that just rejected a batch.
                    break;
                }
            }
        }
    }
    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::{Event, EventKind};
    use crate::notify::NotifyError;
    use crate::notify::DryRunNotifier;
    use async_trait::async_trait;
    use figment::{
        providers::{Format, Serialized, Toml},
        Figment,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn settings(batch_window: &str, urgent_immediate: bool) -> Settings {
        Figment::from(Serialized::defaults(Settings::default()))
            .merge(Toml::string(&format!(
                r#"
                [[channel]]
                name = "mail"
                kind = "smtp"
                host = "localhost"
                port = 1025
                tls = "none"
                from = "a@b.c"
                to = ["d@e.f"]
                batch_window = "{batch_window}"
                urgent_immediate = {urgent_immediate}
                "#
            )))
            .extract()
            .unwrap()
    }

    fn alert(cve: &str, urgent: bool) -> Alert {
        Alert {
            watch: "nginx".into(),
            cve_id: cve.into(),
            event: Event {
                kind: if urgent { EventKind::KevAdded } else { EventKind::New },
                detail: "detail".into(),
                fingerprint: format!("fp-{cve}"),
            },
            confidence: "high".into(),
            match_kind: "cpe".into(),
            evidence: "evidence".into(),
            severity: Some("HIGH".into()),
            score: Some(7.5),
            description: Some("desc".into()),
            in_kev: urgent,
            kev_due_date: None,
            kev_ransomware: false,
            urgent,
            url: format!("https://nvd.nist.gov/vuln/detail/{cve}"),
        }
    }

    /// Seeds a match plus one pending outbox row, with a chosen creation time.
    async fn seed(db: &Db, cve: &str, urgent: bool, created_at: &str) -> i64 {
        let a = alert(cve, urgent);
        let (cve, created_at) = (cve.to_string(), created_at.to_string());
        let payload = serde_json::to_string(&a).unwrap();
        let kind = a.event.kind.as_str().to_string();
        let fp = a.event.fingerprint.clone();
        db.call(move |c| {
            c.execute(
                "INSERT OR IGNORE INTO watches (name, enabled, definition, def_hash, updated_at)
                 VALUES ('nginx', 1, '{}', 'h', 'now')",
                [],
            )?;
            c.execute(
                "INSERT INTO matches (watch_name, cve_id, match_kind, confidence, evidence,
                                      first_matched_at)
                 VALUES ('nginx', ?1, 'cpe', 'high', 'e', 'now')",
                rusqlite::params![cve],
            )?;
            let match_id = c.last_insert_rowid();
            c.execute(
                "INSERT INTO notifications (match_id, channel, event_kind, event_fingerprint,
                                            payload, state, attempts, next_attempt_at, created_at)
                 VALUES (?1, 'mail', ?2, ?3, ?4, 'pending', 0, ?5, ?5)",
                rusqlite::params![match_id, kind, fp, payload, created_at],
            )?;
            Ok(c.last_insert_rowid())
        })
        .await
        .unwrap()
    }

    fn old_ts() -> String {
        crate::timeutil::nvd_format(
            Timestamp::now()
                .checked_sub(jiff::Span::new().hours(2))
                .unwrap(),
        )
    }

    fn notifiers(n: Arc<dyn Notifier>) -> BTreeMap<String, Arc<dyn Notifier>> {
        BTreeMap::from([("mail".to_string(), n)])
    }

    #[tokio::test]
    async fn an_aged_batch_is_delivered_as_one_message() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("15m", true);
        for i in 0..40 {
            seed(&db, &format!("CVE-2026-{i}"), false, &old_ts()).await;
        }
        let dry = Arc::new(DryRunNotifier::new("mail"));
        let stats = drain(&db, &s, &notifiers(dry.clone()), false).await.unwrap();

        assert_eq!(stats.sent, 40);
        assert_eq!(stats.held, 0);
        let sent = dry.sent.lock().unwrap();
        assert_eq!(sent.len(), 1, "40 matches must be one digest, not 40 emails");
        assert_eq!(sent[0].len(), 40);
    }

    #[tokio::test]
    async fn a_fresh_batch_is_held_for_the_window() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("15m", true);
        seed(&db, "CVE-2026-1", false, &queries::now()).await;

        let dry = Arc::new(DryRunNotifier::new("mail"));
        let stats = drain(&db, &s, &notifiers(dry.clone()), false).await.unwrap();
        assert_eq!(stats.sent, 0);
        assert_eq!(stats.held, 1);
        assert!(dry.sent.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_urgent_alert_bypasses_the_batch_window() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("15m", true);
        seed(&db, "CVE-2026-1", true, &queries::now()).await;

        let dry = Arc::new(DryRunNotifier::new("mail"));
        let stats = drain(&db, &s, &notifiers(dry.clone()), false).await.unwrap();
        assert_eq!(stats.sent, 1, "a KEV addition must not wait 15 minutes");
    }

    #[tokio::test]
    async fn urgent_immediate_false_makes_even_kev_wait() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("15m", false);
        seed(&db, "CVE-2026-1", true, &queries::now()).await;
        let dry = Arc::new(DryRunNotifier::new("mail"));
        let stats = drain(&db, &s, &notifiers(dry), false).await.unwrap();
        assert_eq!(stats.held, 1);
    }

    #[tokio::test]
    async fn force_sends_regardless_of_the_window() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("15m", true);
        seed(&db, "CVE-2026-1", false, &queries::now()).await;
        let dry = Arc::new(DryRunNotifier::new("mail"));
        let stats = drain(&db, &s, &notifiers(dry), true).await.unwrap();
        assert_eq!(stats.sent, 1);
    }

    struct Failing {
        retryable: bool,
        calls: AtomicUsize,
    }
    #[async_trait]
    impl Notifier for Failing {
        fn name(&self) -> &str {
            "mail"
        }
        fn kind(&self) -> &'static str {
            "test"
        }
        async fn send(&self, _: &[Alert]) -> Result<(), NotifyError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let e = anyhow::anyhow!("boom");
            Err(if self.retryable {
                NotifyError::Retryable(e)
            } else {
                NotifyError::Permanent(e)
            })
        }
    }

    #[tokio::test]
    async fn a_retryable_failure_schedules_a_retry_and_keeps_the_row() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("0s", true);
        let id = seed(&db, "CVE-2026-1", false, &queries::now()).await;

        let n: Arc<dyn Notifier> = Arc::new(Failing {
            retryable: true,
            calls: AtomicUsize::new(0),
        });
        let stats = drain(&db, &s, &notifiers(n), false).await.unwrap();
        assert_eq!(stats.retried, 1);
        assert_eq!(stats.failed, 0);

        let (state, attempts, next, err): (String, i64, Option<String>, Option<String>) = db
            .call(move |c| {
                Ok(c.query_row(
                    "SELECT state, attempts, next_attempt_at, last_error
                       FROM notifications WHERE id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(state, "pending", "the alert must not be lost");
        assert_eq!(attempts, 1);
        assert!(next.is_some(), "a backoff must be scheduled");
        assert!(err.unwrap().contains("boom"));
    }

    #[tokio::test]
    async fn a_permanent_failure_retires_the_row_immediately() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("0s", true);
        let id = seed(&db, "CVE-2026-1", false, &queries::now()).await;

        let n: Arc<dyn Notifier> = Arc::new(Failing {
            retryable: false,
            calls: AtomicUsize::new(0),
        });
        let stats = drain(&db, &s, &notifiers(n), false).await.unwrap();
        assert_eq!(stats.failed, 1);
        assert_eq!(stats.retried, 0);

        let state: String = db
            .call(move |c| {
                Ok(c.query_row(
                    "SELECT state FROM notifications WHERE id = ?1",
                    [id],
                    |r| r.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(state, "failed", "a bad credential must not be retried for hours");
    }

    #[tokio::test]
    async fn a_row_is_retired_once_the_retry_budget_runs_out() {
        let db = Db::open_in_memory().unwrap();
        let mut s = settings("0s", true);
        s.notify.max_attempts = 2;
        s.notify.retry_base = Duration::from_secs(0);
        let id = seed(&db, "CVE-2026-1", false, &queries::now()).await;

        let n: Arc<dyn Notifier> = Arc::new(Failing {
            retryable: true,
            calls: AtomicUsize::new(0),
        });
        for _ in 0..3 {
            // Clear the backoff so each pass is actually due.
            db.call(|c| {
                c.execute("UPDATE notifications SET next_attempt_at = NULL", [])?;
                Ok(())
            })
            .await
            .unwrap();
            drain(&db, &s, &notifiers(n.clone()), false).await.unwrap();
        }

        let (state, attempts): (String, i64) = db
            .call(move |c| {
                Ok(c.query_row(
                    "SELECT state, attempts FROM notifications WHERE id = ?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(state, "failed");
        assert_eq!(attempts, 2, "must stop at max_attempts, not keep climbing");
    }

    #[tokio::test]
    async fn a_delivered_row_is_never_sent_twice() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("0s", true);
        seed(&db, "CVE-2026-1", false, &queries::now()).await;

        let dry = Arc::new(DryRunNotifier::new("mail"));
        drain(&db, &s, &notifiers(dry.clone()), false).await.unwrap();
        let second = drain(&db, &s, &notifiers(dry.clone()), false).await.unwrap();

        assert_eq!(second.sent, 0);
        assert_eq!(second.considered, 0, "a sent row must leave the queue");
        assert_eq!(dry.sent.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_large_backlog_is_split_into_max_batch_chunks() {
        let db = Db::open_in_memory().unwrap();
        let mut s = settings("0s", true);
        s.notify.max_batch = 10;
        for i in 0..25 {
            seed(&db, &format!("CVE-2026-{i}"), false, &old_ts()).await;
        }
        let dry = Arc::new(DryRunNotifier::new("mail"));
        let stats = drain(&db, &s, &notifiers(dry.clone()), false).await.unwrap();
        assert_eq!(stats.sent, 25);
        let sent = dry.sent.lock().unwrap();
        assert_eq!(sent.len(), 3, "25 items at max_batch=10 is 3 messages");
        assert_eq!(sent.iter().map(|b| b.len()).collect::<Vec<_>>(), vec![10, 10, 5]);
    }

    #[tokio::test]
    async fn an_unparseable_payload_is_retired_rather_than_blocking_the_channel() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("0s", true);
        seed(&db, "CVE-2026-1", false, &queries::now()).await;
        db.call(|c| {
            c.execute("UPDATE notifications SET payload = 'not json'", [])?;
            Ok(())
        })
        .await
        .unwrap();

        let dry = Arc::new(DryRunNotifier::new("mail"));
        let stats = drain(&db, &s, &notifiers(dry.clone()), false).await.unwrap();
        assert_eq!(stats.failed, 1);
        assert!(dry.sent.lock().unwrap().is_empty());
        let counts = db.call(|c| queries::outbox_counts(c)).await.unwrap();
        assert_eq!(counts, vec![("failed".to_string(), 1)]);
    }

    #[tokio::test]
    async fn requeue_returns_failed_rows_to_the_queue() {
        let db = Db::open_in_memory().unwrap();
        let s = settings("0s", true);
        seed(&db, "CVE-2026-1", false, &queries::now()).await;
        let n: Arc<dyn Notifier> = Arc::new(Failing {
            retryable: false,
            calls: AtomicUsize::new(0),
        });
        drain(&db, &s, &notifiers(n), false).await.unwrap();

        let moved = db.call(|c| queries::requeue_failed(c, None)).await.unwrap();
        assert_eq!(moved, 1);

        let dry = Arc::new(DryRunNotifier::new("mail"));
        let stats = drain(&db, &s, &notifiers(dry.clone()), false).await.unwrap();
        assert_eq!(stats.sent, 1, "after fixing the channel the alert goes out");
    }

    #[test]
    fn backoff_grows_and_is_capped() {
        let base = Duration::from_secs(30);
        let t0 = next_attempt(base, 0).as_second() - Timestamp::now().as_second();
        let t3 = next_attempt(base, 3).as_second() - Timestamp::now().as_second();
        let t99 = next_attempt(base, 99).as_second() - Timestamp::now().as_second();
        assert!(t3 > t0, "backoff must grow: {t0} -> {t3}");
        assert!(t99 <= 3600 + 2, "backoff must stay capped: {t99}");
    }
}
