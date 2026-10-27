//! Ties the stages together: candidates -> matcher -> events -> outbox.
//!
//! Matches and their pending notification rows are written in the same transaction as
//! each other's prerequisites, and nothing is ever sent from here. Delivery is the
//! outbox dispatcher's job, which is what makes a crash mid-run safe.

use crate::config::{Settings, Watch};
use crate::db::{queries, Db};
use crate::events::{self, Event, EventKind};
use crate::matcher::{self, Candidate, Match};
use crate::sources::model::CveSnapshot;
use anyhow::{Context, Result};
use serde::Serialize;

/// What a notification renderer is handed. Frozen into the outbox row at enqueue time so
/// a later NVD change cannot rewrite the history of an alert already queued.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Alert {
    pub watch: String,
    pub cve_id: String,
    pub event: Event,
    pub confidence: String,
    pub match_kind: String,
    pub evidence: String,
    pub severity: Option<String>,
    pub score: Option<f64>,
    pub description: Option<String>,
    pub in_kev: bool,
    pub kev_due_date: Option<String>,
    pub kev_ransomware: bool,
    pub urgent: bool,
    pub url: String,
}

/// What `process` does with the notification rows it derives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Enqueue {
    /// Rows are queued for delivery.
    Live,
    /// Rows are written as `suppressed`: never delivered, but occupying the slot so the
    /// same event cannot be queued for real later. This is what makes a baseline quiet
    /// permanently rather than until the next re-evaluation.
    Suppressed,
}

#[derive(Debug, Default)]
pub struct Outcome {
    pub evaluated: usize,
    pub matched: usize,
    pub new_matches: usize,
    pub events: usize,
    /// Rows queued for delivery.
    pub enqueued: usize,
    /// Rows written as suppressed.
    pub suppressed: usize,
}

/// Evaluates `candidates` against every enabled watch, recording matches and queueing
/// notifications for anything that escalated.
///
/// `snapshots` carries the pre-change state keyed by CVE id, as produced by the NVD
/// upsert. A CVE absent from it is simply treated as having no prior state.
pub async fn process(
    db: &Db,
    settings: &Settings,
    watches: &[Watch],
    candidates: Vec<Candidate>,
    snapshots: &std::collections::HashMap<String, (Option<CveSnapshot>, CveSnapshot)>,
    mode: Enqueue,
) -> Result<Outcome> {
    let mut outcome = Outcome {
        evaluated: candidates.len(),
        ..Default::default()
    };
    if candidates.is_empty() || watches.is_empty() {
        return Ok(outcome);
    }

    // Resolve channels up front so a typo in watches.toml fails before any work, and
    // compile each watch once rather than once per CVE.
    let compiled = matcher::CompiledWatch::compile_all(watches)?;
    let mut routes: Vec<(usize, Vec<String>)> = Vec::new();
    for (i, w) in watches.iter().enumerate() {
        let names = settings
            .channels_for(&w.channels)
            .with_context(|| format!("watch `{}`", w.name))?
            .into_iter()
            .map(|c| c.name.clone())
            .collect();
        routes.push((i, names));
    }

    let mut rows: Vec<queries::OutboxRow> = Vec::new();

    for cand in &candidates {
        for (idx, channels) in &routes {
            let watch = &watches[*idx];
            let Some(m) = compiled[*idx].evaluate(cand) else {
                continue;
            };
            outcome.matched += 1;

            let watch_name = watch.name.clone();
            let cve_id = cand.id.clone();
            let m_cloned = m.clone();
            let recorded = db
                .call(move |c| queries::record_match(c, &watch_name, &cve_id, &m_cloned))
                .await?;
            if recorded.is_new {
                outcome.new_matches += 1;
            }

            // A fresh match against an existing CVE is still "new" for this watch, which
            // is how adding a watch surfaces CVEs that were already stored.
            let (old, new) = match snapshots.get(&cand.id) {
                Some((o, n)) => (o.as_ref(), n.clone()),
                None => (None, synthetic_snapshot(cand)),
            };
            let evs = events::classify(old, &new, recorded.is_new, watch.severity_min);
            outcome.events += evs.len();

            for ev in evs {
                let alert = build_alert(watch, cand, &m, &ev);
                let payload = serde_json::to_string(&alert)?;
                for channel in channels {
                    rows.push(queries::OutboxRow {
                        match_id: recorded.id,
                        channel: channel.clone(),
                        event_kind: ev.kind.as_str().to_string(),
                        event_fingerprint: ev.fingerprint.clone(),
                        payload: payload.clone(),
                    });
                }
            }
        }
    }

    if !rows.is_empty() {
        let state = match mode {
            Enqueue::Live => queries::STATE_PENDING,
            Enqueue::Suppressed => queries::STATE_SUPPRESSED,
        };
        let n = db.call(move |c| queries::enqueue(c, &rows, state)).await?;
        match mode {
            Enqueue::Live => outcome.enqueued = n,
            Enqueue::Suppressed => outcome.suppressed = n,
        }
    }
    Ok(outcome)
}

/// Derives a snapshot from a candidate when the NVD upsert did not supply one, e.g. when
/// re-evaluating the stored corpus after a watch definition changed.
fn synthetic_snapshot(c: &Candidate) -> CveSnapshot {
    CveSnapshot {
        id: c.id.clone(),
        last_modified: String::new(),
        vuln_status: None,
        cvss_score: None,
        cvss_severity: c.severity.map(|s| s.as_str().to_string()),
        in_kev: c.kev.is_some(),
        has_exploit_ref: false,
    }
}

fn build_alert(watch: &Watch, c: &Candidate, m: &Match, ev: &Event) -> Alert {
    Alert {
        watch: watch.name.clone(),
        cve_id: c.id.clone(),
        event: ev.clone(),
        confidence: m.confidence.as_str().to_string(),
        match_kind: m.kind.as_str().to_string(),
        evidence: m.evidence.clone(),
        severity: c.severity.map(|s| s.as_str().to_string()),
        score: None,
        description: c.description.clone(),
        in_kev: c.kev.is_some(),
        kev_due_date: c.kev.as_ref().and_then(|k| k.due_date.clone()),
        kev_ransomware: c.kev.as_ref().is_some_and(|k| k.known_ransomware),
        // A KEV addition or a published exploit skips the batch window.
        urgent: ev.kind.is_urgent()
            || c.severity == Some(crate::config::Severity::Critical)
            || matches!(ev.kind, EventKind::New) && c.kev.is_some(),
        url: format!("https://nvd.nist.gov/vuln/detail/{}", c.id),
    }
}

/// Removes matches that a tightened watch no longer produces.
///
/// Only CVEs present in `candidates` are considered, so a bounded re-evaluation window
/// never deletes a match it did not actually re-check. Adding an exclusion to a watch
/// would otherwise leave its old false positives in `query` output forever.
///
/// Note this deliberately does not re-create matches: deleting and re-inserting would
/// mint a new `match_id`, and the outbox is keyed on it, so every surviving match would
/// re-announce itself as `new`.
pub async fn prune_stale_matches(
    db: &Db,
    watches: &[Watch],
    candidates: &[Candidate],
) -> Result<usize> {
    if candidates.is_empty() {
        return Ok(0);
    }
    let ids: Vec<String> = candidates.iter().map(|c| c.id.clone()).collect();
    let compiled = matcher::CompiledWatch::compile_all(watches)?;
    let mut removed = 0usize;

    for (compiled_watch, watch) in compiled.iter().zip(watches) {
        let (name, ids2) = (watch.name.clone(), ids.clone());
        let existing = db
            .call(move |c| queries::matched_cve_ids(c, &name, &ids2))
            .await?;
        if existing.is_empty() {
            continue;
        }
        let still: std::collections::HashSet<&str> = candidates
            .iter()
            .filter(|c| compiled_watch.evaluate(c).is_some())
            .map(|c| c.id.as_str())
            .collect();

        for cve_id in existing {
            if still.contains(cve_id.as_str()) {
                continue;
            }
            let (name, id) = (watch.name.clone(), cve_id.clone());
            if db
                .call(move |c| queries::delete_match(c, &name, &id))
                .await?
            {
                removed += 1;
                tracing::info!(
                    watch = %watch.name,
                    cve = %cve_id,
                    "dropped a match the watch no longer produces"
                );
            }
        }
    }
    Ok(removed)
}

/// Mirrors the config's watches into the DB, pruning any that were removed. Returns the
/// names whose matching definition changed and therefore need a corpus re-evaluation.
pub async fn reconcile_watches(db: &Db, watches: &[Watch]) -> Result<Vec<String>> {
    let owned: Vec<Watch> = watches.to_vec();
    db.call(move |c| {
        let names: Vec<String> = owned.iter().map(|w| w.name.clone()).collect();
        let removed = queries::prune_watches(c, &names)?;
        if removed > 0 {
            tracing::info!(removed, "pruned watches no longer present in the config");
        }
        let mut changed = Vec::new();
        for w in &owned {
            if queries::upsert_watch(c, w)? {
                changed.push(w.name.clone());
            }
        }
        Ok(changed)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WatchFile;
    use std::collections::HashMap;

    fn settings_with_channel() -> Settings {
        use figment::{providers::{Format, Serialized, Toml}, Figment};
        Figment::from(Serialized::defaults(Settings::default()))
            .merge(Toml::string(
                r#"
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
            .unwrap()
    }

    fn nginx_watches() -> Vec<Watch> {
        let f: WatchFile = toml::from_str(
            r#"
            [[watch]]
            name = "nginx"
            channels = ["mail"]
              [[watch.cpe]]
              vendor = "f5"
              product = "nginx"
              [watch.keywords]
              any = ["nginx"]
            "#,
        )
        .unwrap();
        f.watches
    }

    async fn seed(db: &Db, id: &str, severity: &str, description: &str) {
        let (id, severity, description) =
            (id.to_string(), severity.to_string(), description.to_string());
        db.call(move |c| {
            c.execute(
                "INSERT INTO cves (id, published, last_modified, cvss_severity, cvss_score,
                                   description, raw, first_seen, updated_at)
                 VALUES (?1, '2026-10-01T00:00:00.000', '2026-10-01T00:00:00.000', ?2, 9.8,
                         ?3, '{}', 'now', 'now')",
                rusqlite::params![id, severity, description],
            )?;
            c.execute(
                "INSERT INTO cve_cpes (cve_id, part, vendor, product, version, criteria)
                 VALUES (?1, 'a', 'f5', 'nginx', '1.25.0',
                         'cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*')",
                rusqlite::params![id],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_matching_cve_records_a_match_and_queues_one_alert() {
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let watches = nginx_watches();
        reconcile_watches(&db, &watches).await.unwrap();
        seed(&db, "CVE-2026-1", "CRITICAL", "nginx buffer overflow").await;

        let cands = db
            .call(|c| queries::load_candidates(c, &["CVE-2026-1".to_string()]))
            .await
            .unwrap();
        let out = process(&db, &settings, &watches, cands, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();

        assert_eq!(out.matched, 1);
        assert_eq!(out.new_matches, 1);
        assert_eq!(out.enqueued, 1);
        assert_eq!(db.call(|c| queries::count(c, "matches")).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn re_running_the_pipeline_enqueues_nothing_further() {
        // The single most important regression to guard: this is what stands between the
        // tool and an inbox nobody reads.
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let watches = nginx_watches();
        reconcile_watches(&db, &watches).await.unwrap();
        seed(&db, "CVE-2026-1", "CRITICAL", "nginx buffer overflow").await;

        let load = || {
            let db = db.clone();
            async move {
                db.call(|c| queries::load_candidates(c, &["CVE-2026-1".to_string()]))
                    .await
                    .unwrap()
            }
        };
        let first = process(&db, &settings, &watches, load().await, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();
        let second = process(&db, &settings, &watches, load().await, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();
        let third = process(&db, &settings, &watches, load().await, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();

        assert_eq!(first.enqueued, 1);
        assert_eq!(second.enqueued, 0, "the same event must not re-enqueue");
        assert_eq!(third.enqueued, 0);
        assert_eq!(second.new_matches, 0);
        assert_eq!(
            db.call(|c| queries::count(c, "notifications")).await.unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn a_non_matching_cve_is_ignored() {
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let watches = nginx_watches();
        reconcile_watches(&db, &watches).await.unwrap();
        let id = "CVE-2026-2".to_string();
        db.call({
            let id = id.clone();
            move |c| {
                c.execute(
                    "INSERT INTO cves (id, published, last_modified, cvss_severity,
                                       description, raw, first_seen, updated_at)
                     VALUES (?1, '2026-10-01T00:00:00.000', '2026-10-01T00:00:00.000',
                             'HIGH', 'Apache httpd mod_proxy flaw', '{}', 'now', 'now')",
                    rusqlite::params![id],
                )?;
                Ok(())
            }
        })
        .await
        .unwrap();

        let cands = db.call(move |c| queries::load_candidates(c, &[id])).await.unwrap();
        let out = process(&db, &settings, &watches, cands, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();
        assert_eq!(out.matched, 0);
        assert_eq!(out.enqueued, 0);
    }

    #[tokio::test]
    async fn an_escalation_on_an_existing_match_queues_a_second_alert() {
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let watches = nginx_watches();
        reconcile_watches(&db, &watches).await.unwrap();
        seed(&db, "CVE-2026-3", "HIGH", "nginx flaw").await;

        let cands = db
            .call(|c| queries::load_candidates(c, &["CVE-2026-3".to_string()]))
            .await
            .unwrap();
        process(&db, &settings, &watches, cands.clone(), &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();

        // Now the CVE enters KEV.
        let mut snaps = HashMap::new();
        let old = CveSnapshot {
            id: "CVE-2026-3".into(),
            last_modified: "2026-10-01T00:00:00.000".into(),
            vuln_status: None,
            cvss_score: Some(7.5),
            cvss_severity: Some("HIGH".into()),
            in_kev: false,
            has_exploit_ref: false,
        };
        let new = CveSnapshot { in_kev: true, ..old.clone() };
        snaps.insert("CVE-2026-3".to_string(), (Some(old), new));

        let out = process(&db, &settings, &watches, cands, &snaps, Enqueue::Live).await.unwrap();
        assert_eq!(out.enqueued, 1, "kev_added is a distinct event");
        assert_eq!(
            db.call(|c| queries::count(c, "notifications")).await.unwrap(),
            2
        );
    }

    #[tokio::test]
    async fn changing_a_watch_definition_is_detected_but_renaming_a_channel_is_not() {
        let db = Db::open_in_memory().unwrap();
        let mut watches = nginx_watches();
        assert_eq!(
            reconcile_watches(&db, &watches).await.unwrap(),
            vec!["nginx".to_string()],
            "a watch is 'changed' the first time it is seen"
        );
        assert!(
            reconcile_watches(&db, &watches).await.unwrap().is_empty(),
            "an unchanged definition needs no corpus re-evaluation"
        );

        watches[0].channels = vec!["mail".into(), "other".into()];
        assert!(
            reconcile_watches(&db, &watches).await.unwrap().is_empty(),
            "routing is not a matching concern"
        );

        watches[0].keywords.any.push("njs".into());
        assert_eq!(reconcile_watches(&db, &watches).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn removing_a_watch_prunes_its_matches() {
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let watches = nginx_watches();
        reconcile_watches(&db, &watches).await.unwrap();
        seed(&db, "CVE-2026-4", "CRITICAL", "nginx flaw").await;
        let cands = db
            .call(|c| queries::load_candidates(c, &["CVE-2026-4".to_string()]))
            .await
            .unwrap();
        process(&db, &settings, &watches, cands, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();
        assert_eq!(db.call(|c| queries::count(c, "matches")).await.unwrap(), 1);

        reconcile_watches(&db, &[]).await.unwrap();
        assert_eq!(db.call(|c| queries::count(c, "matches")).await.unwrap(), 0);
        assert_eq!(
            db.call(|c| queries::count(c, "notifications")).await.unwrap(),
            0,
            "cascade must clear the outbox too"
        );
    }

    #[tokio::test]
    async fn tightening_a_watch_drops_its_stale_matches() {
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let mut watches = nginx_watches();
        reconcile_watches(&db, &watches).await.unwrap();
        seed(&db, "CVE-2026-7", "CRITICAL", "nginx proxy manager auth bypass").await;

        let load = || {
            let db = db.clone();
            async move {
                db.call(|c| queries::load_candidates(c, &["CVE-2026-7".to_string()]))
                    .await
                    .unwrap()
            }
        };
        process(&db, &settings, &watches, load().await, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();
        assert_eq!(db.call(|c| queries::count(c, "matches")).await.unwrap(), 1);

        // Add the exclusion that should retire it.
        watches[0].keywords.none = vec!["nginx proxy manager".into()];
        let removed = prune_stale_matches(&db, &watches, &load().await).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(db.call(|c| queries::count(c, "matches")).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn pruning_leaves_matches_that_still_hold() {
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let watches = nginx_watches();
        reconcile_watches(&db, &watches).await.unwrap();
        seed(&db, "CVE-2026-8", "CRITICAL", "nginx buffer overflow").await;
        let cands = db
            .call(|c| queries::load_candidates(c, &["CVE-2026-8".to_string()]))
            .await
            .unwrap();
        process(&db, &settings, &watches, cands.clone(), &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();

        assert_eq!(prune_stale_matches(&db, &watches, &cands).await.unwrap(), 0);
        assert_eq!(db.call(|c| queries::count(c, "matches")).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn pruning_ignores_cves_outside_the_evaluated_set() {
        // A bounded re-evaluation window must never delete a match it did not re-check.
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let watches = nginx_watches();
        reconcile_watches(&db, &watches).await.unwrap();
        seed(&db, "CVE-2026-9", "CRITICAL", "nginx flaw").await;
        let cands = db
            .call(|c| queries::load_candidates(c, &["CVE-2026-9".to_string()]))
            .await
            .unwrap();
        process(&db, &settings, &watches, cands, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();

        // Prune with a candidate set that excludes the matched CVE entirely.
        seed(&db, "CVE-2026-10", "HIGH", "apache httpd flaw").await;
        let other = db
            .call(|c| queries::load_candidates(c, &["CVE-2026-10".to_string()]))
            .await
            .unwrap();
        assert_eq!(prune_stale_matches(&db, &watches, &other).await.unwrap(), 0);
        assert_eq!(
            db.call(|c| queries::count(c, "matches")).await.unwrap(),
            1,
            "an unevaluated match must survive"
        );
    }

    #[tokio::test]
    async fn a_suppressed_pass_records_the_event_so_it_can_never_go_live() {
        // The baseline's guarantee. A suppressed row is not delivered, and a later live
        // pass over the same CVE (a re-evaluation, `vedette match`, a KEV cycle with no
        // prior snapshot) finds the slot taken and queues nothing.
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let watches = nginx_watches();
        reconcile_watches(&db, &watches).await.unwrap();
        seed(&db, "CVE-2026-5", "CRITICAL", "nginx flaw").await;
        let load = || {
            let db = db.clone();
            async move {
                db.call(|c| queries::load_candidates(c, &["CVE-2026-5".to_string()]))
                    .await
                    .unwrap()
            }
        };
        let quiet = process(&db, &settings, &watches, load().await, &HashMap::new(), Enqueue::Suppressed)
            .await
            .unwrap();
        assert_eq!(quiet.matched, 1);
        assert_eq!(quiet.enqueued, 0);
        assert_eq!(quiet.suppressed, 1);

        let live = process(&db, &settings, &watches, load().await, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap();
        assert_eq!(live.enqueued, 0, "the baseline already accounted for this event");
        let pending = db
            .call(|c| Ok(c.query_row(
                "SELECT COUNT(*) FROM notifications WHERE state = 'pending'", [],
                |r| r.get::<_, i64>(0))?))
            .await
            .unwrap();
        assert_eq!(pending, 0);
    }

    #[tokio::test]
    async fn a_watch_pointing_at_an_unknown_channel_fails_loudly() {
        let db = Db::open_in_memory().unwrap();
        let settings = settings_with_channel();
        let mut watches = nginx_watches();
        watches[0].channels = vec!["nope".into()];
        reconcile_watches(&db, &watches).await.unwrap();
        seed(&db, "CVE-2026-6", "CRITICAL", "nginx flaw").await;
        let cands = db
            .call(|c| queries::load_candidates(c, &["CVE-2026-6".to_string()]))
            .await
            .unwrap();
        let err = process(&db, &settings, &watches, cands, &HashMap::new(), Enqueue::Live)
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("unknown channel"), "{err:#}");
    }
}
