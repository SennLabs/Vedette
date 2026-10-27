//! Hand-written SQL. Grouped by table so the call sites stay free of string literals.

use anyhow::Result;
use jiff::Timestamp;
use rusqlite::{named_params, Connection, OptionalExtension};

pub fn now() -> String {
    Timestamp::now().to_string()
}

// ---------------------------------------------------------------- sync_state

#[derive(Debug, Clone, Default)]
pub struct SyncState {
    pub cursor: Option<String>,
    pub extra: Option<String>,
    pub last_success: Option<String>,
    pub last_error: Option<String>,
    pub last_attempt: Option<String>,
}

pub fn get_sync_state(conn: &Connection, source: &str) -> Result<SyncState> {
    let row = conn
        .query_row(
            "SELECT cursor, extra, last_success, last_error, last_attempt
               FROM sync_state WHERE source = ?1",
            [source],
            |r| {
                Ok(SyncState {
                    cursor: r.get(0)?,
                    extra: r.get(1)?,
                    last_success: r.get(2)?,
                    last_error: r.get(3)?,
                    last_attempt: r.get(4)?,
                })
            },
        )
        .optional()?;
    Ok(row.unwrap_or_default())
}

pub fn mark_sync_attempt(conn: &Connection, source: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO sync_state (source, last_attempt) VALUES (?1, ?2)
         ON CONFLICT(source) DO UPDATE SET last_attempt = excluded.last_attempt",
        rusqlite::params![source, now()],
    )?;
    Ok(())
}

/// Records a completed sync. The cursor is only ever advanced here, so a failed window
/// leaves the previous watermark in place and the next run re-fetches rather than skips.
pub fn mark_sync_success(
    conn: &Connection,
    source: &str,
    cursor: Option<&str>,
    extra: Option<&str>,
) -> Result<()> {
    conn.execute(
        "INSERT INTO sync_state (source, cursor, extra, last_success, last_error, last_attempt)
              VALUES (:source, :cursor, :extra, :now, NULL, :now)
         ON CONFLICT(source) DO UPDATE SET
              cursor       = COALESCE(:cursor, sync_state.cursor),
              extra        = COALESCE(:extra,  sync_state.extra),
              last_success = :now,
              last_error   = NULL,
              last_attempt = :now",
        named_params! { ":source": source, ":cursor": cursor, ":extra": extra, ":now": now() },
    )?;
    Ok(())
}

pub fn mark_sync_error(conn: &Connection, source: &str, error: &str) -> Result<()> {
    conn.execute(
        "INSERT INTO sync_state (source, last_error, last_attempt)
              VALUES (:source, :err, :now)
         ON CONFLICT(source) DO UPDATE SET last_error = :err, last_attempt = :now",
        named_params! { ":source": source, ":err": error, ":now": now() },
    )?;
    Ok(())
}

// ---------------------------------------------------------------------- cves

use crate::sources::model::{CveDelta, CveSnapshot, NvdCve};

/// The comparison state for one CVE, or `None` when it has never been stored.
///
/// A placeholder row created by KEV ingest counts as *not yet seen* for escalation
/// purposes: it carries no NVD data to diff against, so the first real NVD sighting is a
/// genuine arrival rather than a change.
pub fn snapshot(conn: &Connection, cve_id: &str) -> Result<Option<CveSnapshot>> {
    let base = conn
        .query_row(
            "SELECT last_modified, vuln_status, cvss_score, cvss_severity, placeholder
               FROM cves WHERE id = ?1",
            [cve_id],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<f64>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                    r.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((last_modified, vuln_status, cvss_score, cvss_severity, placeholder)) = base else {
        return Ok(None);
    };
    if placeholder != 0 {
        return Ok(None);
    }
    Ok(Some(CveSnapshot {
        id: cve_id.to_string(),
        last_modified,
        vuln_status,
        cvss_score,
        cvss_severity,
        in_kev: is_in_kev(conn, cve_id)?,
        has_exploit_ref: has_exploit_ref(conn, cve_id)?,
    }))
}

/// True when any stored reference carries NVD's `Exploit` tag.
pub fn has_exploit_ref(conn: &Connection, cve_id: &str) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT 1 FROM cve_refs
              WHERE cve_id = ?1 AND tags LIKE '%\"Exploit\"%' LIMIT 1",
            [cve_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some())
}

/// Stores a batch of CVEs and reports what changed, for the escalation differ.
///
/// Everything happens in one transaction: either the whole page lands or none of it does,
/// so a crash cannot leave a CVE row without its CPE rows.
pub fn upsert_cves(conn: &mut Connection, cves: &[NvdCve]) -> Result<Vec<CveDelta>> {
    let ts = now();
    let tx = conn.transaction()?;
    let mut deltas = Vec::with_capacity(cves.len());
    {
        let mut ins_cve = tx.prepare(
            "INSERT INTO cves (id, published, last_modified, vuln_status, description,
                               cvss_version, cvss_score, cvss_severity, cvss_vector, cwes,
                               raw, placeholder, first_seen, updated_at)
             VALUES (:id, :published, :last_modified, :status, :descr, :cvss_v, :cvss_score,
                     :cvss_sev, :cvss_vec, :cwes, :raw, 0, :now, :now)
             ON CONFLICT(id) DO UPDATE SET
                 published     = excluded.published,
                 last_modified = excluded.last_modified,
                 vuln_status   = excluded.vuln_status,
                 description   = excluded.description,
                 cvss_version  = excluded.cvss_version,
                 cvss_score    = excluded.cvss_score,
                 cvss_severity = excluded.cvss_severity,
                 cvss_vector   = excluded.cvss_vector,
                 cwes          = excluded.cwes,
                 raw           = excluded.raw,
                 -- A real NVD record always clears the KEV-created placeholder flag.
                 placeholder   = 0,
                 updated_at    = excluded.updated_at",
        )?;
        let mut del_cpes = tx.prepare("DELETE FROM cve_cpes WHERE cve_id = ?1")?;
        let mut ins_cpe = tx.prepare(
            "INSERT INTO cve_cpes (cve_id, part, vendor, product, version, criteria,
                                   ver_start, ver_start_incl, ver_end, ver_end_incl)
             VALUES (:cve, :part, :vendor, :product, :version, :criteria,
                     :vstart, :vstart_incl, :vend, :vend_incl)",
        )?;
        // References accumulate rather than being replaced: NVD occasionally drops a
        // reference on re-analysis, and losing the Exploit tag we already alerted on
        // would make the escalation re-fire later.
        let mut ins_ref = tx.prepare(
            "INSERT INTO cve_refs (cve_id, url, tags) VALUES (:cve, :url, :tags)
             ON CONFLICT(cve_id, url) DO UPDATE SET tags = excluded.tags",
        )?;

        for cve in cves {
            let old = snapshot(&tx, &cve.id)?;
            let (cvss_v, cvss_score, cvss_sev, cvss_vec) = match cve.best_cvss() {
                Some((v, s, sev, vec)) => (Some(v), s, sev, vec),
                None => (None, None, None, None),
            };
            ins_cve.execute(named_params! {
                ":id": &cve.id,
                ":published": &cve.published,
                ":last_modified": &cve.last_modified,
                ":status": &cve.vuln_status,
                ":descr": cve.english_description(),
                ":cvss_v": &cvss_v,
                ":cvss_score": cvss_score,
                ":cvss_sev": &cvss_sev,
                ":cvss_vec": &cvss_vec,
                ":cwes": serde_json::to_string(&cve.cwe_ids())?,
                ":raw": serde_json::to_string(cve)?,
                ":now": &ts,
            })?;

            del_cpes.execute([&cve.id])?;
            for row in cve.cpe_rows() {
                ins_cpe.execute(named_params! {
                    ":cve": &cve.id,
                    ":part": &row.part,
                    ":vendor": &row.vendor,
                    ":product": &row.product,
                    ":version": &row.version,
                    ":criteria": &row.criteria,
                    ":vstart": &row.ver_start,
                    ":vstart_incl": row.ver_start_incl as i64,
                    ":vend": &row.ver_end,
                    ":vend_incl": row.ver_end_incl as i64,
                })?;
            }
            for r in &cve.references {
                ins_ref.execute(named_params! {
                    ":cve": &cve.id,
                    ":url": &r.url,
                    ":tags": serde_json::to_string(&r.tags)?,
                })?;
            }

            let new = CveSnapshot {
                id: cve.id.clone(),
                last_modified: cve.last_modified.clone(),
                vuln_status: cve.vuln_status.clone(),
                cvss_score,
                cvss_severity: cvss_sev,
                in_kev: is_in_kev(&tx, &cve.id)?,
                has_exploit_ref: has_exploit_ref(&tx, &cve.id)?,
            };
            deltas.push(CveDelta {
                id: cve.id.clone(),
                is_new: old.is_none(),
                old,
                new,
            });
        }
    }
    tx.commit()?;
    Ok(deltas)
}

// ---------------------------------------------------------------------- kev

/// Upserts the whole catalog and returns the CVE ids that were not previously stored.
///
/// A KEV entry routinely names a CVE that NVD has not analysed yet. Rather than drop it,
/// a placeholder `cves` row is created so the matcher can act on the KEV text immediately;
/// NVD fills the row in on a later poll and clears the flag. KEV is the time-critical
/// feed, so it must never block on NVD.
pub fn upsert_kev(conn: &mut Connection, entries: &[crate::sources::model::KevEntry]) -> Result<Vec<String>> {
    let tx = conn.transaction()?;
    let ts = now();
    let mut newly_added = Vec::new();
    {
        let mut known = tx.prepare("SELECT 1 FROM kev WHERE cve_id = ?1")?;
        let mut upsert = tx.prepare(
            "INSERT INTO kev (
                 cve_id, vendor_project, product, vulnerability_name, date_added, due_date,
                 short_description, required_action, known_ransomware, forensic_triage,
                 notes, cwes, first_seen)
             VALUES (:cve_id, :vendor, :product, :vname, :added, :due, :descr, :action,
                     :ransom, :triage, :notes, :cwes, :now)
             ON CONFLICT(cve_id) DO UPDATE SET
                 vendor_project     = excluded.vendor_project,
                 product            = excluded.product,
                 vulnerability_name = excluded.vulnerability_name,
                 date_added         = excluded.date_added,
                 due_date           = excluded.due_date,
                 short_description  = excluded.short_description,
                 required_action    = excluded.required_action,
                 known_ransomware   = excluded.known_ransomware,
                 forensic_triage    = excluded.forensic_triage,
                 notes              = excluded.notes,
                 cwes               = excluded.cwes",
        )?;
        // A placeholder carries no NVD data; `placeholder = 1` marks it as awaiting NVD.
        // The DO NOTHING matters: a real NVD row must never be downgraded to a placeholder.
        let mut placeholder = tx.prepare(
            "INSERT INTO cves (id, published, last_modified, vuln_status, description,
                               raw, placeholder, first_seen, updated_at)
             VALUES (:id, :added, :added, 'Awaiting Analysis', :descr, '{}', 1, :now, :now)
             ON CONFLICT(id) DO NOTHING",
        )?;

        for e in entries {
            if !known.exists([&e.cve_id])? {
                newly_added.push(e.cve_id.clone());
            }
            let cwes = serde_json::to_string(&e.cwes)?;
            upsert.execute(named_params! {
                ":cve_id": &e.cve_id,
                ":vendor": &e.vendor_project,
                ":product": &e.product,
                ":vname": &e.vulnerability_name,
                ":added": &e.date_added,
                ":due": &e.due_date,
                ":descr": &e.short_description,
                ":action": &e.required_action,
                ":ransom": &e.known_ransomware_campaign_use,
                ":triage": &e.forensic_triage,
                ":notes": &e.notes,
                ":cwes": cwes,
                ":now": &ts,
            })?;
            placeholder.execute(named_params! {
                ":id": &e.cve_id,
                // KEV gives a date, not a timestamp; normalize so ordering still works.
                ":added": e.date_added.as_deref().map(|d| format!("{d}T00:00:00Z")),
                ":descr": &e.short_description,
                ":now": &ts,
            })?;
        }
    }
    tx.commit()?;
    Ok(newly_added)
}

pub fn is_in_kev(conn: &Connection, cve_id: &str) -> Result<bool> {
    Ok(conn.query_row("SELECT 1 FROM kev WHERE cve_id = ?1", [cve_id], |_| Ok(()))
        .optional()?
        .is_some())
}

// ---------------------------------------------------------------- counts

pub fn count(conn: &Connection, table: &str) -> Result<i64> {
    // `table` is never user input; every call site passes a literal.
    let sql = format!("SELECT COUNT(*) FROM {table}");
    Ok(conn.query_row(&sql, [], |r| r.get(0))?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    #[test]
    fn sync_state_starts_empty_then_records_progress() {
        let db = Db::open_in_memory().unwrap();
        db.blocking(|c| {
            let s = get_sync_state(c, "nvd")?;
            assert!(s.cursor.is_none() && s.last_success.is_none());

            mark_sync_success(c, "nvd", Some("2026-10-01T00:00:00Z"), None)?;
            let s = get_sync_state(c, "nvd")?;
            assert_eq!(s.cursor.as_deref(), Some("2026-10-01T00:00:00Z"));
            assert!(s.last_success.is_some());

            // An error must not clobber the watermark.
            mark_sync_error(c, "nvd", "boom")?;
            let s = get_sync_state(c, "nvd")?;
            assert_eq!(s.cursor.as_deref(), Some("2026-10-01T00:00:00Z"));
            assert_eq!(s.last_error.as_deref(), Some("boom"));

            // A success with no cursor keeps the existing one.
            mark_sync_success(c, "nvd", None, Some("v2"))?;
            let s = get_sync_state(c, "nvd")?;
            assert_eq!(s.cursor.as_deref(), Some("2026-10-01T00:00:00Z"));
            assert_eq!(s.extra.as_deref(), Some("v2"));
            assert!(s.last_error.is_none(), "success clears the error");
            Ok(())
        })
        .unwrap();
    }
}

// ------------------------------------------------------------------- watches

/// Mirrors a watch definition into the DB. Returns true when the matching-relevant part
/// changed, which tells the caller to re-evaluate the stored corpus against it.
pub fn upsert_watch(conn: &Connection, watch: &crate::config::Watch) -> Result<bool> {
    let hash = watch.def_hash();
    let previous: Option<String> = conn
        .query_row(
            "SELECT def_hash FROM watches WHERE name = ?1",
            [&watch.name],
            |r| r.get(0),
        )
        .optional()?;
    conn.execute(
        "INSERT INTO watches (name, enabled, definition, def_hash, updated_at)
              VALUES (:name, :enabled, :def, :hash, :now)
         ON CONFLICT(name) DO UPDATE SET
              enabled    = excluded.enabled,
              definition = excluded.definition,
              def_hash   = excluded.def_hash,
              updated_at = excluded.updated_at",
        named_params! {
            ":name": &watch.name,
            ":enabled": watch.enabled as i64,
            ":def": watch.definition_json(),
            ":hash": &hash,
            ":now": now(),
        },
    )?;
    Ok(previous.as_deref() != Some(hash.as_str()))
}

/// Forgets watches that are no longer in the config, taking their matches with them.
pub fn prune_watches(conn: &Connection, keep: &[String]) -> Result<usize> {
    let existing: Vec<String> = {
        let mut stmt = conn.prepare("SELECT name FROM watches")?;
        let rows = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows
    };
    let mut removed = 0;
    for name in existing {
        if !keep.iter().any(|k| k == &name) {
            // ON DELETE CASCADE clears matches and their outbox rows.
            conn.execute("DELETE FROM watches WHERE name = ?1", [&name])?;
            removed += 1;
        }
    }
    Ok(removed)
}

// ---------------------------------------------------------------- candidates

use crate::matcher::{Candidate, CandidateCpe, CandidateKev};

/// Loads everything the matcher needs for the given CVE ids.
///
/// Four queries total regardless of batch size: a per-CVE loop would issue tens of
/// thousands of statements during a backfill. Ids go through a temp table rather than an
/// `IN (...)` list to stay clear of SQLite's bound-parameter ceiling.
pub fn load_candidates(conn: &Connection, ids: &[String]) -> Result<Vec<Candidate>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS _cand_ids (id TEXT PRIMARY KEY);
         DELETE FROM _cand_ids;",
    )?;
    {
        let mut ins = conn.prepare("INSERT OR IGNORE INTO _cand_ids (id) VALUES (?1)")?;
        for id in ids {
            ins.execute([id])?;
        }
    }

    let mut out: std::collections::BTreeMap<String, Candidate> = Default::default();
    {
        let mut stmt = conn.prepare(
            "SELECT c.id, c.description, c.cvss_severity
               FROM cves c JOIN _cand_ids t ON t.id = c.id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, Option<String>>(2)?,
            ))
        })?;
        for row in rows {
            let (id, description, severity) = row?;
            out.insert(
                id.clone(),
                Candidate {
                    id,
                    description,
                    severity: severity
                        .as_deref()
                        .and_then(crate::config::Severity::parse_nvd),
                    ..Default::default()
                },
            );
        }
    }
    {
        let mut stmt = conn.prepare(
            "SELECT p.cve_id, p.vendor, p.product, p.version, p.criteria,
                    p.ver_start, p.ver_start_incl, p.ver_end, p.ver_end_incl
               FROM cve_cpes p JOIN _cand_ids t ON t.id = p.cve_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                CandidateCpe {
                    vendor: r.get(1)?,
                    product: r.get(2)?,
                    version: r.get(3)?,
                    criteria: r.get(4)?,
                    ver_start: r.get(5)?,
                    ver_start_incl: r.get::<_, Option<i64>>(6)?.unwrap_or(0) != 0,
                    ver_end: r.get(7)?,
                    ver_end_incl: r.get::<_, Option<i64>>(8)?.unwrap_or(0) != 0,
                },
            ))
        })?;
        for row in rows {
            let (id, cpe) = row?;
            if let Some(c) = out.get_mut(&id) {
                c.cpes.push(cpe);
            }
        }
    }
    {
        let mut stmt = conn.prepare(
            "SELECT r.cve_id, r.url FROM cve_refs r JOIN _cand_ids t ON t.id = r.cve_id",
        )?;
        let rows = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for row in rows {
            let (id, url) = row?;
            if let Some(c) = out.get_mut(&id) {
                c.reference_urls.push(url);
            }
        }
    }
    {
        let mut stmt = conn.prepare(
            "SELECT k.cve_id, k.vendor_project, k.product, k.vulnerability_name,
                    k.due_date, k.known_ransomware
               FROM kev k JOIN _cand_ids t ON t.id = k.cve_id",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                CandidateKev {
                    vendor_project: r.get(1)?,
                    product: r.get(2)?,
                    vulnerability_name: r.get(3)?,
                    due_date: r.get(4)?,
                    known_ransomware: r
                        .get::<_, Option<String>>(5)?
                        .is_some_and(|v| v.eq_ignore_ascii_case("known")),
                },
            ))
        })?;
        for row in rows {
            let (id, kev) = row?;
            if let Some(c) = out.get_mut(&id) {
                c.kev = Some(kev);
            }
        }
    }
    Ok(out.into_values().collect())
}

/// Every stored CVE id. Used by the quiet pass that closes a baseline, which must cover
/// the whole corpus rather than the window one sync happened to fetch.
pub fn all_cve_ids(conn: &Connection) -> Result<Vec<String>> {
    let mut stmt = conn.prepare("SELECT id FROM cves ORDER BY published DESC")?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// CVE ids published at or after `since`, newest first.
pub fn cve_ids_published_since(conn: &Connection, since: &str, limit: usize) -> Result<Vec<String>> {
    let mut stmt = conn.prepare(
        "SELECT id FROM cves WHERE published >= ?1 ORDER BY published DESC LIMIT ?2",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![since, limit as i64], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// ------------------------------------------------------------------- matches

pub struct RecordedMatch {
    pub id: i64,
    pub is_new: bool,
}

/// Inserts or strengthens a match. Confidence only ever moves up: once a CVE has been
/// confirmed by CPE data, a later keyword-only re-evaluation must not weaken it.
pub fn record_match(
    conn: &Connection,
    watch_name: &str,
    cve_id: &str,
    m: &crate::matcher::Match,
) -> Result<RecordedMatch> {
    let existing: Option<(i64, String)> = conn
        .query_row(
            "SELECT id, confidence FROM matches WHERE watch_name = ?1 AND cve_id = ?2",
            rusqlite::params![watch_name, cve_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;

    if let Some((id, current)) = existing {
        let upgrade = current == "review" && m.confidence == crate::matcher::Confidence::High;
        if upgrade {
            conn.execute(
                "UPDATE matches SET match_kind = ?1, confidence = ?2, evidence = ?3
                  WHERE id = ?4",
                rusqlite::params![m.kind.as_str(), m.confidence.as_str(), &m.evidence, id],
            )?;
        }
        return Ok(RecordedMatch { id, is_new: false });
    }

    conn.execute(
        "INSERT INTO matches (watch_name, cve_id, match_kind, confidence, evidence,
                              first_matched_at)
         VALUES (:watch, :cve, :kind, :conf, :evidence, :now)",
        named_params! {
            ":watch": watch_name,
            ":cve": cve_id,
            ":kind": m.kind.as_str(),
            ":conf": m.confidence.as_str(),
            ":evidence": &m.evidence,
            ":now": now(),
        },
    )?;
    Ok(RecordedMatch {
        id: conn.last_insert_rowid(),
        is_new: true,
    })
}

pub fn match_count(conn: &Connection, watch_name: &str) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM matches WHERE watch_name = ?1",
        [watch_name],
        |r| r.get(0),
    )?)
}

// ------------------------------------------------------------------- outbox

#[derive(Debug, Clone)]
pub struct OutboxRow {
    pub match_id: i64,
    pub channel: String,
    pub event_kind: String,
    pub event_fingerprint: String,
    pub payload: String,
}

/// Outbox rows the dispatcher will deliver.
pub const STATE_PENDING: &str = "pending";
/// Outbox rows written during a baseline: never delivered, never retried, but present so
/// the same event cannot be enqueued for real by a later re-evaluation.
pub const STATE_SUPPRESSED: &str = "suppressed";

/// Enqueues notifications in `state`, returning how many were genuinely new.
///
/// `INSERT OR IGNORE` against `UNIQUE(match_id, channel, event_fingerprint)` is the
/// idempotency guarantee: re-running the whole pipeline over the same data enqueues
/// nothing a second time, so a crashed or repeated sync cannot double-send. A row written
/// as `suppressed` occupies the same slot, which is how a baseline stays silent forever
/// rather than until the next `vedette match`.
pub fn enqueue(conn: &mut Connection, rows: &[OutboxRow], state: &str) -> Result<usize> {
    if rows.is_empty() {
        return Ok(0);
    }
    let ts = now();
    let tx = conn.transaction()?;
    let mut inserted = 0usize;
    {
        let mut stmt = tx.prepare(
            "INSERT OR IGNORE INTO notifications
                 (match_id, channel, event_kind, event_fingerprint, payload, state,
                  attempts, next_attempt_at, created_at)
             VALUES (:match_id, :channel, :kind, :fp, :payload, :state, 0, :now, :now)",
        )?;
        for r in rows {
            inserted += stmt.execute(named_params! {
                ":match_id": r.match_id,
                ":channel": &r.channel,
                ":kind": &r.event_kind,
                ":fp": &r.event_fingerprint,
                ":payload": &r.payload,
                ":state": state,
                ":now": &ts,
            })?;
        }
    }
    tx.commit()?;
    Ok(inserted)
}

pub fn outbox_counts(conn: &Connection) -> Result<Vec<(String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT state, COUNT(*) FROM notifications GROUP BY state ORDER BY state",
    )?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

// -------------------------------------------------------- outbox dispatching

#[derive(Debug, Clone)]
pub struct PendingRow {
    pub id: i64,
    pub channel: String,
    pub event_kind: String,
    pub payload: String,
    pub attempts: u32,
    pub created_at: String,
}

/// Pending rows for one channel whose backoff has elapsed, oldest first.
pub fn pending_for_channel(
    conn: &Connection,
    channel: &str,
    now_ts: &str,
    limit: usize,
) -> Result<Vec<PendingRow>> {
    let mut stmt = conn.prepare(
        "SELECT id, channel, event_kind, payload, attempts, created_at
           FROM notifications
          WHERE state = 'pending'
            AND channel = ?1
            AND (next_attempt_at IS NULL OR next_attempt_at <= ?2)
          ORDER BY created_at ASC, id ASC
          LIMIT ?3",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![channel, now_ts, limit as i64], |r| {
            Ok(PendingRow {
                id: r.get(0)?,
                channel: r.get(1)?,
                event_kind: r.get(2)?,
                payload: r.get(3)?,
                attempts: r.get::<_, i64>(4)? as u32,
                created_at: r.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

pub fn mark_sent(conn: &mut Connection, ids: &[i64]) -> Result<()> {
    let ts = now();
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "UPDATE notifications
                SET state = 'sent', sent_at = ?2, last_error = NULL, next_attempt_at = NULL
              WHERE id = ?1",
        )?;
        for id in ids {
            stmt.execute(rusqlite::params![id, &ts])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Records a failed attempt. A row that has exhausted `max_attempts` is retired to
/// `failed` so the dispatcher stops reconsidering it on every cycle.
pub fn mark_attempt_failed(
    conn: &mut Connection,
    ids: &[i64],
    error: &str,
    next_attempt_at: &str,
    max_attempts: u32,
) -> Result<usize> {
    let tx = conn.transaction()?;
    let mut retired = 0usize;
    {
        let mut stmt = tx.prepare(
            "UPDATE notifications
                SET attempts         = attempts + 1,
                    last_error       = :err,
                    next_attempt_at  = :next,
                    state            = CASE WHEN attempts + 1 >= :max THEN 'failed'
                                            ELSE 'pending' END
              WHERE id = :id",
        )?;
        let mut check = tx.prepare("SELECT state FROM notifications WHERE id = ?1")?;
        for id in ids {
            stmt.execute(named_params! {
                ":err": error,
                ":next": next_attempt_at,
                ":max": max_attempts as i64,
                ":id": id,
            })?;
            let state: String = check.query_row([id], |r| r.get(0))?;
            if state == "failed" {
                retired += 1;
            }
        }
    }
    tx.commit()?;
    Ok(retired)
}

/// Retires rows immediately, without consuming the retry budget. Used for a permanent
/// failure such as a rejected credential.
pub fn mark_permanently_failed(conn: &mut Connection, ids: &[i64], error: &str) -> Result<()> {
    let tx = conn.transaction()?;
    {
        let mut stmt = tx.prepare(
            "UPDATE notifications
                SET state = 'failed', attempts = attempts + 1, last_error = ?2,
                    next_attempt_at = NULL
              WHERE id = ?1",
        )?;
        for id in ids {
            stmt.execute(rusqlite::params![id, error])?;
        }
    }
    tx.commit()?;
    Ok(())
}

/// Returns failed rows to the queue, e.g. after fixing a credential.
pub fn requeue_failed(conn: &Connection, channel: Option<&str>) -> Result<usize> {
    let n = match channel {
        Some(c) => conn.execute(
            "UPDATE notifications
                SET state = 'pending', attempts = 0, next_attempt_at = NULL
              WHERE state = 'failed' AND channel = ?1",
            [c],
        )?,
        None => conn.execute(
            "UPDATE notifications
                SET state = 'pending', attempts = 0, next_attempt_at = NULL
              WHERE state = 'failed'",
            [],
        )?,
    };
    Ok(n)
}

/// One row of `notify status`: channel, state, count, most recent error.
pub type OutboxSummaryRow = (String, String, i64, Option<String>);

/// Per-channel outbox summary for `notify status`.
pub fn outbox_by_channel(conn: &Connection) -> Result<Vec<OutboxSummaryRow>> {
    let mut stmt = conn.prepare(
        "SELECT channel, state, COUNT(*), MAX(last_error)
           FROM notifications GROUP BY channel, state ORDER BY channel, state",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

/// Deletes a watch's match for one CVE. Used when a tightened watch no longer matches it.
///
/// The cascade also removes that match's outbox rows. Those were already delivered (or
/// retired), so this is housekeeping, not a lost alert.
pub fn delete_match(conn: &Connection, watch_name: &str, cve_id: &str) -> Result<bool> {
    let n = conn.execute(
        "DELETE FROM matches WHERE watch_name = ?1 AND cve_id = ?2",
        rusqlite::params![watch_name, cve_id],
    )?;
    Ok(n > 0)
}

/// CVE ids this watch currently has matches for, restricted to `ids`.
///
/// The restriction matters: pruning must only ever consider CVEs that were actually
/// re-evaluated, or a limited re-evaluation window would delete matches it never checked.
pub fn matched_cve_ids(conn: &Connection, watch_name: &str, ids: &[String]) -> Result<Vec<String>> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    conn.execute_batch(
        "CREATE TEMP TABLE IF NOT EXISTS _prune_ids (id TEXT PRIMARY KEY);
         DELETE FROM _prune_ids;",
    )?;
    {
        let mut ins = conn.prepare("INSERT OR IGNORE INTO _prune_ids (id) VALUES (?1)")?;
        for id in ids {
            ins.execute([id])?;
        }
    }
    let mut stmt = conn.prepare(
        "SELECT m.cve_id FROM matches m JOIN _prune_ids t ON t.id = m.cve_id
          WHERE m.watch_name = ?1",
    )?;
    let rows = stmt
        .query_map([watch_name], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}
