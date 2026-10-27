//! CISA Known Exploited Vulnerabilities catalog ingest.
//!
//! The catalog is a single ~1.8 MB JSON document, so the sync is conditional: an
//! unchanged catalog costs one 304 rather than a full download every hour.
//!
//! Verified against the live endpoint on 2026-10-26: cisa.gov sends both `ETag` and
//! `Last-Modified`, but **ignores `If-None-Match`** (answers 200 with the full body) and
//! honours only `If-Modified-Since`. Both validators are therefore stored and both
//! headers sent, so the saving does not depend on which one the origin decides to respect.

use super::retry::{self, Attempt, Policy};
use super::{model::KevCatalog, retry_after};
use crate::db::{queries, Db};
use anyhow::{Context, Result};
use reqwest::{header, Client, StatusCode};
use std::time::Duration;

pub const SOURCE: &str = "kev";

/// Cache validators from the previous fetch, persisted as JSON in `sync_state.cursor`.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct Validators {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    /// The raw `Last-Modified` header value, replayed verbatim as `If-Modified-Since`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

impl Validators {
    fn is_empty(&self) -> bool {
        self.etag.is_none() && self.last_modified.is_none()
    }

    fn decode(stored: Option<&str>) -> Self {
        let Some(raw) = stored else {
            return Self::default();
        };
        serde_json::from_str(raw).unwrap_or_else(|_| Self {
            // Tolerate a cursor written before validators became a JSON object.
            etag: Some(raw.to_string()),
            last_modified: None,
        })
    }

    fn encode(&self) -> Option<String> {
        if self.is_empty() {
            return None;
        }
        serde_json::to_string(self).ok()
    }
}

#[derive(Debug)]
pub enum Fetch {
    NotModified,
    Catalog {
        validators: Validators,
        catalog: KevCatalog,
    },
}

#[derive(Debug, Default, PartialEq)]
pub struct SyncOutcome {
    pub not_modified: bool,
    pub catalog_version: Option<String>,
    pub total: usize,
    /// CVE ids present in the catalog that this instance had never seen before. These are
    /// the `kev_added` events.
    pub newly_added: Vec<String>,
    /// True on the first successful fetch, when every catalog entry back to 2021 is
    /// "newly added". Callers record those matches without alerting, as for NVD.
    pub baseline: bool,
}

pub struct KevClient {
    http: Client,
    url: String,
    policy: Policy,
}

impl KevClient {
    pub fn new(http: Client, url: impl Into<String>) -> Self {
        Self {
            http,
            url: url.into(),
            policy: Policy::default(),
        }
    }

    pub async fn fetch(&self, validators: &Validators) -> Result<Fetch> {
        retry::run(self.policy, "kev fetch", |_attempt| {
            let mut req = self.http.get(&self.url);
            if let Some(tag) = &validators.etag {
                req = req.header(header::IF_NONE_MATCH, tag);
            }
            if let Some(lm) = &validators.last_modified {
                req = req.header(header::IF_MODIFIED_SINCE, lm);
            }
            async move {
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => return (Attempt::Retry(e.into()), None),
                };
                let status = resp.status();
                let hint = retry_after(resp.headers());

                if status == StatusCode::NOT_MODIFIED {
                    return (Attempt::Done(Fetch::NotModified), None);
                }
                if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
                    return (
                        Attempt::Retry(anyhow::anyhow!("CISA returned {status}")),
                        hint,
                    );
                }
                if !status.is_success() {
                    return (
                        Attempt::Fatal(anyhow::anyhow!("CISA returned {status}")),
                        None,
                    );
                }

                let header_str = |name: header::HeaderName| {
                    resp.headers()
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_owned)
                };
                let fresh = Validators {
                    etag: header_str(header::ETAG),
                    last_modified: header_str(header::LAST_MODIFIED),
                };
                let body = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => return (Attempt::Retry(e.into()), None),
                };
                // A truncated or HTML error body is a transport problem worth retrying,
                // not a permanent one.
                match serde_json::from_slice::<KevCatalog>(&body) {
                    Ok(catalog) => (
                        Attempt::Done(Fetch::Catalog {
                            validators: fresh,
                            catalog,
                        }),
                        None,
                    ),
                    Err(e) => (
                        Attempt::Retry(
                            anyhow::Error::new(e).context("parsing the KEV catalog JSON"),
                        ),
                        None,
                    ),
                }
            }
        })
        .await
    }
}

/// Fetches the catalog and stores it. Returns which CVE ids are newly known to be
/// exploited; the caller turns those into `kev_added` notifications.
pub async fn sync(db: &Db, client: &KevClient, force: bool) -> Result<SyncOutcome> {
    let stored = db
        .call(|c| queries::get_sync_state(c, SOURCE))
        .await
        .context("reading the KEV sync watermark")?;
    db.call(|c| queries::mark_sync_attempt(c, SOURCE)).await?;

    let baseline = stored.last_success.is_none();
    let validators = if force {
        Validators::default()
    } else {
        Validators::decode(stored.cursor.as_deref())
    };
    let fetched = match client.fetch(&validators).await {
        Ok(f) => f,
        Err(e) => {
            let msg = format!("{e:#}");
            db.call(move |c| queries::mark_sync_error(c, SOURCE, &msg)).await?;
            return Err(e);
        }
    };

    let (fresh, catalog) = match fetched {
        Fetch::NotModified => {
            tracing::info!("KEV catalog unchanged (304)");
            db.call(|c| queries::mark_sync_success(c, SOURCE, None, None)).await?;
            return Ok(SyncOutcome {
                not_modified: true,
                catalog_version: stored.extra,
                ..Default::default()
            });
        }
        Fetch::Catalog { validators, catalog } => (validators, catalog),
    };

    if catalog.count != catalog.vulnerabilities.len() {
        // Worth knowing about, but the array is the authority — act on what arrived.
        tracing::warn!(
            declared = catalog.count,
            received = catalog.vulnerabilities.len(),
            "KEV catalog count disagrees with its own array length"
        );
    }

    let version = catalog.catalog_version.clone();
    let total = catalog.vulnerabilities.len();
    let newly_added = db
        .call(move |c| queries::upsert_kev(c, &catalog.vulnerabilities))
        .await
        .context("storing the KEV catalog")?;

    let (v, cursor) = (version.clone(), fresh.encode());
    db.call(move |c| queries::mark_sync_success(c, SOURCE, cursor.as_deref(), Some(&v)))
        .await?;

    tracing::info!(
        catalog_version = %version,
        total,
        newly_added = newly_added.len(),
        "KEV catalog stored"
    );
    Ok(SyncOutcome {
        not_modified: false,
        catalog_version: Some(version),
        total,
        newly_added,
        baseline,
    })
}

/// The KEV catalog updates roughly daily; an hour is responsive without being wasteful
/// given the conditional request.
pub const DEFAULT_POLL: Duration = Duration::from_secs(3600);

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{header_exists, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const FIXTURE: &str = include_str!("../../tests/fixtures/kev.json");
    const LAST_MOD: &str = "Fri, 23 Oct 2026 19:30:18 GMT";

    fn client(server: &MockServer) -> KevClient {
        let mut c = KevClient::new(
            super::super::http_client().unwrap(),
            format!("{}/kev.json", server.uri()),
        );
        c.policy = Policy {
            max_attempts: 3,
            base: Duration::from_millis(1),
            cap: Duration::from_millis(5),
        };
        c
    }

    /// A full-catalog 200 carrying both cache validators.
    fn ok_response() -> ResponseTemplate {
        ResponseTemplate::new(200)
            .set_body_raw(FIXTURE, "application/json")
            .insert_header("etag", "\"v1\"")
            .insert_header("last-modified", LAST_MOD)
    }

    /// Mounts "200 with the catalog, unless the request is conditional, then 304".
    ///
    /// Routing is on `header_exists` rather than `header(name, value)`: wiremock 0.6
    /// splits header values on commas, so an HTTP-date value can never match that way.
    /// Exact values are asserted against `received_requests()` instead.
    async fn mount_conditional(server: &MockServer) {
        // The first-mounted matching mock wins, so the guarded 304 goes first.
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .and(header_exists("if-modified-since"))
            .respond_with(ResponseTemplate::new(304))
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ok_response())
            .mount(server)
            .await;
    }

    async fn sent_header(server: &MockServer, nth: usize, name: &str) -> Option<String> {
        let reqs = server.received_requests().await.unwrap();
        reqs.get(nth)?
            .headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    }

    #[tokio::test]
    async fn loads_the_real_catalog_and_counts_additions() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ok_response())
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let out = sync(&db, &client(&server), false).await.unwrap();

        assert!(!out.not_modified);
        assert_eq!(out.total, 1756, "the captured catalog holds 1756 entries");
        assert_eq!(out.newly_added.len(), 1756, "everything is new on a cold start");
        assert!(out.baseline, "and none of it is an alert");
        assert_eq!(out.catalog_version.as_deref(), Some("2026.10.23"));

        let stored = db.call(|c| queries::count(c, "kev")).await.unwrap();
        assert_eq!(stored, 1756);

        // Both validators must be persisted so the next poll can be conditional.
        let st = db.call(|c| queries::get_sync_state(c, SOURCE)).await.unwrap();
        let v = Validators::decode(st.cursor.as_deref());
        assert_eq!(v.etag.as_deref(), Some("\"v1\""));
        assert_eq!(v.last_modified.as_deref(), Some(LAST_MOD));
        assert!(st.last_success.is_some() && st.last_error.is_none());
    }

    #[tokio::test]
    async fn a_second_sync_is_a_no_op_via_if_modified_since() {
        // cisa.gov ignores If-None-Match and honours only If-Modified-Since (verified
        // against the live endpoint), so the 304 path hinges on the date validator.
        let server = MockServer::start().await;
        mount_conditional(&server).await;

        let db = Db::open_in_memory().unwrap();
        let c = client(&server);
        sync(&db, &c, false).await.unwrap();
        let second = sync(&db, &c, false).await.unwrap();

        assert!(second.not_modified, "unchanged catalog must cost a 304");
        assert!(second.newly_added.is_empty());
        // The stored catalog version survives a 304.
        assert_eq!(second.catalog_version.as_deref(), Some("2026.10.23"));
    }

    #[tokio::test]
    async fn both_validators_are_replayed_verbatim() {
        let server = MockServer::start().await;
        mount_conditional(&server).await;

        let db = Db::open_in_memory().unwrap();
        let c = client(&server);
        sync(&db, &c, false).await.unwrap();
        sync(&db, &c, false).await.unwrap();

        // The cold-start request must carry neither validator.
        assert_eq!(sent_header(&server, 0, "if-modified-since").await, None);
        assert_eq!(sent_header(&server, 0, "if-none-match").await, None);
        // The second must replay both, byte for byte.
        assert_eq!(
            sent_header(&server, 1, "if-modified-since").await.as_deref(),
            Some(LAST_MOD)
        );
        assert_eq!(
            sent_header(&server, 1, "if-none-match").await.as_deref(),
            Some("\"v1\"")
        );
    }

    #[tokio::test]
    async fn force_ignores_stored_validators() {
        let server = MockServer::start().await;
        mount_conditional(&server).await;

        let db = Db::open_in_memory().unwrap();
        let c = client(&server);
        sync(&db, &c, false).await.unwrap();
        let forced = sync(&db, &c, true).await.unwrap();

        assert!(!forced.not_modified, "force must bypass the 304 shortcut");
        assert_eq!(forced.total, 1756);
        assert_eq!(sent_header(&server, 1, "if-modified-since").await, None);
    }

    #[tokio::test]
    async fn only_genuinely_new_cve_ids_are_reported() {
        let server = MockServer::start().await;
        // Serve the catalog minus its first entry once, then the full catalog, so exactly
        // one CVE shows up as an addition on the second sync.
        let mut doc: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        let all = doc["vulnerabilities"].as_array().unwrap().clone();
        let held_back = all[0].clone();
        doc["vulnerabilities"] = serde_json::Value::Array(all[1..].to_vec());

        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&doc))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(FIXTURE, "application/json"))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let c = client(&server);
        let first = sync(&db, &c, false).await.unwrap();
        assert_eq!(first.newly_added.len(), 1755);

        let second = sync(&db, &c, false).await.unwrap();
        assert!(!second.baseline, "only the first fetch is a baseline");
        assert_eq!(second.total, 1756);
        assert_eq!(
            second.newly_added,
            vec![held_back["cveID"].as_str().unwrap().to_string()],
            "re-seeing 1755 entries must not re-announce them"
        );
    }

    #[tokio::test]
    async fn kev_entries_create_placeholder_cves_so_matching_never_waits_on_nvd() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ok_response())
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        sync(&db, &client(&server), false).await.unwrap();

        let (cves, placeholders) = db
            .call(|c| {
                Ok((
                    queries::count(c, "cves")?,
                    c.query_row("SELECT COUNT(*) FROM cves WHERE placeholder = 1", [], |r| {
                        r.get::<_, i64>(0)
                    })?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(cves, 1756);
        assert_eq!(placeholders, 1756, "NVD has not filled these in yet");
    }

    #[tokio::test]
    async fn a_server_error_retries_then_leaves_the_watermark_untouched() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let err = sync(&db, &client(&server), false).await.unwrap_err();
        assert!(format!("{err:#}").contains("gave up after 3"));

        let st = db.call(|c| queries::get_sync_state(c, SOURCE)).await.unwrap();
        assert!(st.cursor.is_none(), "a failed sync must not store validators");
        assert!(st.last_error.is_some());
        assert!(st.last_success.is_none());
    }

    #[tokio::test]
    async fn a_client_error_is_fatal_and_not_retried() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let err = sync(&db, &client(&server), false).await.unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("403"), "{msg}");
        assert!(!msg.contains("gave up after"), "403 must not be retried: {msg}");
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn truncated_json_is_treated_as_transient() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/kev.json"))
            .respond_with(ResponseTemplate::new(200).set_body_raw("{\"vulnerabi", "application/json"))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let err = sync(&db, &client(&server), false).await.unwrap_err();
        assert!(format!("{err:#}").contains("gave up after 3"));
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[test]
    fn a_legacy_bare_etag_cursor_still_decodes() {
        let v = Validators::decode(Some("\"opaque-etag\""));
        assert_eq!(v.etag.as_deref(), Some("\"opaque-etag\""));
        assert!(v.last_modified.is_none());
        assert!(Validators::decode(None).is_empty());
    }
}
