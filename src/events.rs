//! Escalation classification.
//!
//! NVD re-touches old CVEs in bulk: a `lastModified` bump on its own means nothing and
//! must not produce a notification. This module decides which changes are worth waking
//! someone for, and gives each one a fingerprint so re-running the differ is idempotent.

use crate::config::Severity;
use crate::sources::model::CveSnapshot;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// The first time this (watch, CVE) pair matched.
    New,
    /// The CVE entered the CISA KEV catalog. The most urgent signal available.
    KevAdded,
    /// A reference tagged `Exploit` appeared.
    ExploitRef,
    /// The CVSS base score went up.
    ScoreIncrease,
    /// Severity crossed the watch's floor upward, e.g. unscored -> HIGH.
    SeverityThreshold,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "new",
            Self::KevAdded => "kev_added",
            Self::ExploitRef => "exploit_ref",
            Self::ScoreIncrease => "score_increase",
            Self::SeverityThreshold => "severity_threshold",
        }
    }

    /// Whether this event skips a channel's batch window.
    pub fn is_urgent(&self) -> bool {
        matches!(self, Self::KevAdded | Self::ExploitRef)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub kind: EventKind,
    /// Human-readable reason, used verbatim in the notification.
    pub detail: String,
    /// Stable hash over the event's salient values, so the same escalation enqueues once.
    pub fingerprint: String,
}

fn fingerprint(kind: EventKind, parts: &[&str]) -> String {
    let mut h = Sha256::new();
    h.update(kind.as_str().as_bytes());
    for p in parts {
        h.update(b"\x1f");
        h.update(p.as_bytes());
    }
    hex::encode(h.finalize())[..32].to_string()
}

fn fmt_score(s: Option<f64>) -> String {
    s.map(|v| format!("{v:.1}")).unwrap_or_else(|| "none".into())
}

/// Classifies what changed between two sightings of a CVE.
///
/// `is_new_match` is true when the (watch, CVE) pair had never matched before, which is
/// independent of whether the CVE itself is new: adding a watch makes old CVEs new matches.
pub fn classify(
    old: Option<&CveSnapshot>,
    new: &CveSnapshot,
    is_new_match: bool,
    severity_floor: Option<Severity>,
) -> Vec<Event> {
    let mut out = Vec::new();

    if is_new_match {
        out.push(Event {
            kind: EventKind::New,
            detail: format!(
                "new match ({}{})",
                new.cvss_severity.as_deref().unwrap_or("unscored"),
                new.cvss_score.map(|s| format!(" {s:.1}")).unwrap_or_default()
            ),
            // Keyed on the CVE alone: a given pair announces its arrival exactly once,
            // no matter how many times the differ runs.
            fingerprint: fingerprint(EventKind::New, &[&new.id]),
        });
    }

    // KEV entry. Reported even on a first match, because "new" alone would bury the one
    // fact that makes this CVE urgent.
    let kev_is_new = new.in_kev && !old.map(|o| o.in_kev).unwrap_or(false);
    if kev_is_new {
        out.push(Event {
            kind: EventKind::KevAdded,
            detail: "added to the CISA KEV catalog: actively exploited".to_string(),
            fingerprint: fingerprint(EventKind::KevAdded, &[&new.id]),
        });
    }

    let Some(old) = old else {
        // Nothing to diff against; the events above are the whole story.
        return out;
    };

    if new.has_exploit_ref && !old.has_exploit_ref {
        out.push(Event {
            kind: EventKind::ExploitRef,
            detail: "a reference tagged `Exploit` was published".to_string(),
            fingerprint: fingerprint(EventKind::ExploitRef, &[&new.id]),
        });
    }

    match (old.cvss_score, new.cvss_score) {
        (Some(o), Some(n)) if n > o => out.push(Event {
            kind: EventKind::ScoreIncrease,
            detail: format!("CVSS rose from {o:.1} to {n:.1}"),
            fingerprint: fingerprint(
                EventKind::ScoreIncrease,
                &[&new.id, &fmt_score(Some(o)), &fmt_score(Some(n))],
            ),
        }),
        // Unscored -> scored is the common and important case: a CVE published without
        // analysis gets its first score days later, and it can be a 9.8.
        (None, Some(n)) => out.push(Event {
            kind: EventKind::ScoreIncrease,
            detail: format!("scored for the first time: CVSS {n:.1}"),
            fingerprint: fingerprint(
                EventKind::ScoreIncrease,
                &[&new.id, "none", &fmt_score(Some(n))],
            ),
        }),
        _ => {}
    }

    // Crossing the watch's own floor upward deserves its own event: a MEDIUM that becomes
    // HIGH under a `severity_min = "high"` watch was previously being filtered out.
    if let Some(floor) = severity_floor {
        let old_sev = old.cvss_severity.as_deref().and_then(Severity::parse_nvd);
        let new_sev = new.cvss_severity.as_deref().and_then(Severity::parse_nvd);
        if let Some(ns) = new_sev {
            let was_below = old_sev.map(|os| os < floor).unwrap_or(true);
            if ns >= floor && was_below {
                out.push(Event {
                    kind: EventKind::SeverityThreshold,
                    detail: format!(
                        "severity rose from {} to {}, crossing the {} threshold",
                        old_sev.map(|s| s.as_str()).unwrap_or("unscored"),
                        ns.as_str(),
                        floor.as_str()
                    ),
                    fingerprint: fingerprint(
                        EventKind::SeverityThreshold,
                        &[
                            &new.id,
                            old_sev.map(|s| s.as_str()).unwrap_or("unscored"),
                            ns.as_str(),
                        ],
                    ),
                });
            }
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(score: Option<f64>, sev: Option<&str>) -> CveSnapshot {
        CveSnapshot {
            id: "CVE-2026-1".into(),
            last_modified: "2026-01-01T00:00:00.000".into(),
            vuln_status: Some("Analyzed".into()),
            cvss_score: score,
            cvss_severity: sev.map(str::to_string),
            in_kev: false,
            has_exploit_ref: false,
        }
    }

    #[test]
    fn a_first_match_is_one_new_event() {
        let n = snap(Some(9.8), Some("CRITICAL"));
        let ev = classify(None, &n, true, None);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::New);
        assert!(ev[0].detail.contains("CRITICAL 9.8"), "{}", ev[0].detail);
    }

    #[test]
    fn a_cosmetic_republish_emits_nothing() {
        // This is the whole point of the module: NVD re-touches old CVEs in bulk, and a
        // bare lastModified bump must stay silent or the alerts stop being read.
        let old = snap(Some(7.5), Some("HIGH"));
        let mut new = old.clone();
        new.last_modified = "2026-06-01T00:00:00.000".into();
        assert!(classify(Some(&old), &new, false, None).is_empty());
    }

    #[test]
    fn a_score_increase_is_reported() {
        let old = snap(Some(7.5), Some("HIGH"));
        let new = snap(Some(9.8), Some("CRITICAL"));
        let ev = classify(Some(&old), &new, false, None);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::ScoreIncrease);
        assert!(ev[0].detail.contains("7.5 to 9.8"), "{}", ev[0].detail);
    }

    #[test]
    fn a_score_decrease_is_not_an_escalation() {
        let old = snap(Some(9.8), Some("CRITICAL"));
        let new = snap(Some(7.5), Some("HIGH"));
        assert!(classify(Some(&old), &new, false, None).is_empty());
    }

    #[test]
    fn first_ever_score_counts_as_an_increase() {
        // The Awaiting Analysis -> Analyzed transition, which can land at 9.8.
        let old = snap(None, None);
        let new = snap(Some(9.8), Some("CRITICAL"));
        let ev = classify(Some(&old), &new, false, None);
        assert_eq!(ev[0].kind, EventKind::ScoreIncrease);
        assert!(ev[0].detail.contains("scored for the first time"));
    }

    #[test]
    fn entering_kev_is_reported_even_for_an_old_cve() {
        let old = snap(Some(5.0), Some("MEDIUM"));
        let mut new = old.clone();
        new.in_kev = true;
        let ev = classify(Some(&old), &new, false, None);
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::KevAdded);
        assert!(ev[0].kind.is_urgent());
    }

    #[test]
    fn staying_in_kev_is_not_re_reported() {
        let mut old = snap(Some(5.0), Some("MEDIUM"));
        old.in_kev = true;
        let mut new = old.clone();
        new.last_modified = "2026-09-09T00:00:00.000".into();
        assert!(classify(Some(&old), &new, false, None).is_empty());
    }

    #[test]
    fn a_new_match_that_is_already_in_kev_reports_both() {
        // "new" alone would bury the one fact that makes it urgent.
        let mut new = snap(Some(9.1), Some("CRITICAL"));
        new.in_kev = true;
        let ev = classify(None, &new, true, None);
        let kinds: Vec<_> = ev.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&EventKind::New));
        assert!(kinds.contains(&EventKind::KevAdded));
    }

    #[test]
    fn a_new_exploit_reference_is_reported_once() {
        let old = snap(Some(7.5), Some("HIGH"));
        let mut new = old.clone();
        new.has_exploit_ref = true;
        let ev = classify(Some(&old), &new, false, None);
        assert_eq!(ev[0].kind, EventKind::ExploitRef);
        assert!(ev[0].kind.is_urgent());

        // Already known: silent.
        assert!(classify(Some(&new), &new, false, None).is_empty());
    }

    #[test]
    fn crossing_the_watch_floor_upward_is_its_own_event() {
        let old = snap(Some(5.0), Some("MEDIUM"));
        let new = snap(Some(8.1), Some("HIGH"));
        let ev = classify(Some(&old), &new, false, Some(Severity::High));
        let kinds: Vec<_> = ev.iter().map(|e| e.kind).collect();
        assert!(kinds.contains(&EventKind::SeverityThreshold));
        assert!(kinds.contains(&EventKind::ScoreIncrease));
    }

    #[test]
    fn staying_above_the_floor_does_not_re_announce_the_threshold() {
        let old = snap(Some(8.1), Some("HIGH"));
        let new = snap(Some(9.0), Some("HIGH"));
        let ev = classify(Some(&old), &new, false, Some(Severity::High));
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].kind, EventKind::ScoreIncrease, "only the score moved");
    }

    #[test]
    fn fingerprints_are_stable_and_distinguish_events() {
        let old = snap(Some(7.5), Some("HIGH"));
        let new = snap(Some(9.8), Some("CRITICAL"));
        let a = classify(Some(&old), &new, false, None);
        let b = classify(Some(&old), &new, false, None);
        assert_eq!(a[0].fingerprint, b[0].fingerprint, "re-running must be idempotent");

        // A different magnitude is a different event and must notify again.
        let bigger = snap(Some(10.0), Some("CRITICAL"));
        let c = classify(Some(&old), &bigger, false, None);
        assert_ne!(a[0].fingerprint, c[0].fingerprint);

        // Different kinds never collide.
        let mut kev = old.clone();
        kev.in_kev = true;
        let d = classify(Some(&old), &kev, false, None);
        assert_ne!(a[0].fingerprint, d[0].fingerprint);
    }

    #[test]
    fn a_new_match_fingerprint_is_independent_of_the_score() {
        // Otherwise a re-scored CVE would re-announce itself as "new".
        let a = classify(None, &snap(Some(7.5), Some("HIGH")), true, None);
        let b = classify(None, &snap(Some(9.8), Some("CRITICAL")), true, None);
        assert_eq!(a[0].fingerprint, b[0].fingerprint);
    }
}
