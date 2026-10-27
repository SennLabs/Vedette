//! NVD CVE API 2.0 ingest.
//!
//! Three constraints shape this module, all verified against the live API:
//!
//! 1. **Rate limit.** 50 requests per rolling 30 s with an API key, 5 without. The
//!    configured default of 45 leaves headroom so a retry burst cannot trip it.
//! 2. **120-day window cap.** `lastModStartDate`/`lastModEndDate` must both be present
//!    and span at most 120 days. A wider span answers with a bare **404** and no error
//!    body, which is indistinguishable from "no results" unless handled deliberately.
//! 3. **Watermark discipline.** The cursor only advances after a window completes in
//!    full, so an interrupted backfill re-fetches rather than silently skipping CVEs.

use super::model::{NvdCve, NvdCveResponse};
use super::retry::{self, Attempt, Policy};
use super::retry_after;
use crate::config::{NvdSettings, NVD_MAX_WINDOW_DAYS};
use crate::db::{queries, Db};
use crate::sources::model::CveDelta;
use crate::timeutil;
use anyhow::{Context, Result};
use governor::{Quota, RateLimiter};
use jiff::Timestamp;
use reqwest::{Client, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use std::num::NonZeroU32;
use std::sync::Arc;

pub const SOURCE: &str = "nvd";

/// NVD's documented limit for unauthenticated clients: 5 requests per rolling 30 s.
/// The configured `rate_limit` assumes a key, so without one it must be clamped or every
/// request past the fifth earns a 403 and the sync degenerates into backoff.
pub const KEYLESS_RATE_LIMIT: u32 = 5;

type Limiter = RateLimiter<
    governor::state::direct::NotKeyed,
    governor::state::InMemoryState,
    governor::clock::DefaultClock,
    governor::middleware::NoOpMiddleware<governor::clock::QuantaInstant>,
>;

pub struct NvdClient {
    http: Client,
    base_url: String,
    api_key: Option<SecretString>,
    limiter: Arc<Limiter>,
    policy: Policy,
    page_size: u32,
    /// The rate actually enforced, after the keyless clamp. Read only by the test that
    /// guards the clamp against regressing.
    #[cfg_attr(not(test), allow(dead_code))]
    effective_rate: u32,
}

/// One candidate from the CPE dictionary, used by `watch suggest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeSuggestion {
    pub vendor: String,
    pub product: String,
    pub title: Option<String>,
    /// How many dictionary entries share this vendor/product pair.
    pub entries: usize,
}

impl NvdClient {
    pub fn new(http: Client, settings: &NvdSettings, api_key: Option<SecretString>) -> Result<Self> {
        let mut rate = settings.rate_limit;
        if api_key.is_none() && rate > KEYLESS_RATE_LIMIT {
            tracing::warn!(
                configured = rate,
                effective = KEYLESS_RATE_LIMIT,
                "no NVD API key: clamping the request rate to the public limit. Set \
                 NVD_API_KEY to sync roughly ten times faster."
            );
            rate = KEYLESS_RATE_LIMIT;
        }
        let limit = NonZeroU32::new(rate).context("nvd.rate_limit must be at least 1")?;
        // One cell per (window / limit), burst up to `limit`: `limit` requests per window.
        let period = settings
            .rate_window
            .checked_div(rate)
            .context("nvd.rate_window / rate_limit underflowed")?;
        let quota = Quota::with_period(period)
            .context("nvd.rate_window is too small for the configured rate_limit")?
            .allow_burst(limit);
        Ok(Self {
            http,
            base_url: settings.base_url.trim_end_matches('/').to_string(),
            api_key,
            limiter: Arc::new(RateLimiter::direct(quota)),
            policy: Policy::default(),
            page_size: settings.page_size,
            effective_rate: rate,
        })
    }

    async fn get_json<T: serde::de::DeserializeOwned>(
        &self,
        path: &str,
        params: &[(&str, String)],
        label: &str,
    ) -> Result<T> {
        retry::run(self.policy, label, |_attempt| {
            let url = format!("{}/{path}", self.base_url);
            let mut req = self.http.get(&url);
            // NVD's valueless flags (hasKev, noRejected) are passed with an empty value;
            // verified against the live API that `hasKev=` and bare `hasKev` return
            // identical results.
            req = req.query(params);
            if let Some(key) = &self.api_key {
                req = req.header("apiKey", key.expose_secret());
            }
            let limiter = Arc::clone(&self.limiter);
            async move {
                limiter.until_ready().await;
                let resp = match req.send().await {
                    Ok(r) => r,
                    Err(e) => return (Attempt::Retry(e.into()), None),
                };
                let status = resp.status();
                let hint = retry_after(resp.headers());

                // NVD signals throttling with 403 as often as 429.
                if status == StatusCode::FORBIDDEN
                    || status == StatusCode::TOO_MANY_REQUESTS
                    || status.is_server_error()
                {
                    let detail = resp
                        .headers()
                        .get("message")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    return (
                        Attempt::Retry(anyhow::anyhow!("NVD returned {status} {detail}").context(
                            "NVD is throttling or unavailable",
                        )),
                        hint,
                    );
                }
                if status == StatusCode::NOT_FOUND {
                    // Not "no results" — NVD answers an out-of-range date window this way.
                    return (
                        Attempt::Fatal(anyhow::anyhow!(
                            "NVD returned 404 for {url}; this normally means a request \
                             parameter was rejected, most often a lastModified window \
                             wider than 120 days"
                        )),
                        None,
                    );
                }
                if !status.is_success() {
                    return (
                        Attempt::Fatal(anyhow::anyhow!("NVD returned {status} for {url}")),
                        None,
                    );
                }

                let body = match resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => return (Attempt::Retry(e.into()), None),
                };
                match serde_json::from_slice::<T>(&body) {
                    Ok(v) => (Attempt::Done(v), None),
                    Err(e) => (
                        Attempt::Retry(anyhow::Error::new(e).context("parsing the NVD response")),
                        None,
                    ),
                }
            }
        })
        .await
    }

    /// Fetches every CVE modified in `[start, end]`, following pagination.
    ///
    /// The caller is responsible for keeping the span inside NVD's 120-day cap; this
    /// asserts it rather than trusting it, because the failure mode is a silent 404.
    pub async fn cves_modified_between(
        &self,
        start: Timestamp,
        end: Timestamp,
    ) -> Result<Vec<NvdCve>> {
        let span_days = (end.as_second() - start.as_second()) / 86_400;
        anyhow::ensure!(
            span_days <= NVD_MAX_WINDOW_DAYS,
            "refusing to request a {span_days}-day window: NVD caps lastModified spans at \
             120 days and answers a wider one with a bare 404"
        );

        let mut out = Vec::new();
        let mut start_index = 0u32;
        loop {
            let params = vec![
                ("lastModStartDate", timeutil::nvd_format(start)),
                ("lastModEndDate", timeutil::nvd_format(end)),
                ("resultsPerPage", self.page_size.to_string()),
                ("startIndex", start_index.to_string()),
                ("noRejected", String::new()),
            ];
            let label = format!(
                "nvd cves {}..{} @{}",
                timeutil::nvd_format(start),
                timeutil::nvd_format(end),
                start_index
            );
            let page: NvdCveResponse = self.get_json("cves/2.0", &params, &label).await?;

            let received = page.vulnerabilities.len() as u32;
            out.extend(page.vulnerabilities.into_iter().map(|v| v.cve));
            // At info level: a window is fetched whole before it is written, and a page
            // can take a minute, so without this the first sync looks hung for an hour.
            tracing::info!(
                fetched = out.len(),
                total = page.total_results,
                "NVD page received"
            );

            start_index += received.max(1);
            if received == 0 || start_index >= page.total_results {
                break;
            }
        }
        Ok(out)
    }

    /// Resolves a product name to CPE vendor/product candidates, so a watch can be
    /// written against the right vendor. Product names are not unique: `nginx` appears
    /// under `f5`, `nginx` and `igor_sysoev`.
    pub async fn suggest_cpes(&self, term: &str, limit: usize) -> Result<Vec<CpeSuggestion>> {
        #[derive(serde::Deserialize)]
        struct CpeResponse {
            #[serde(rename = "totalResults")]
            total: u32,
            #[serde(default)]
            products: Vec<CpeProduct>,
        }
        #[derive(serde::Deserialize)]
        struct CpeProduct {
            cpe: CpeBody,
        }
        #[derive(serde::Deserialize)]
        struct CpeBody {
            #[serde(rename = "cpeName")]
            cpe_name: String,
            #[serde(default)]
            titles: Vec<CpeTitle>,
        }
        #[derive(serde::Deserialize)]
        struct CpeTitle {
            title: String,
            lang: String,
        }

        // Every page must be read before grouping. A partial read ranks vendors by their
        // position in the dictionary rather than by how much they actually ship: for
        // `nginx`, one 500-entry page puts `igor_sysoev` on top and omits `f5` entirely,
        // when the full 3342-entry set has `f5:nginx` first by a wide margin.
        //
        // The CPE endpoint accepts resultsPerPage up to 10000 (unlike cves/2.0, capped at
        // 2000), so the whole set is normally one request.
        const CPE_PAGE: u32 = 10_000;
        let mut grouped: std::collections::BTreeMap<(String, String), (usize, Option<String>)> =
            Default::default();
        let mut start_index = 0u32;
        let mut total;
        loop {
            let params = vec![
                ("keywordSearch", term.to_string()),
                ("resultsPerPage", CPE_PAGE.to_string()),
                ("startIndex", start_index.to_string()),
            ];
            let resp: CpeResponse = self
                .get_json(
                    "cpes/2.0",
                    &params,
                    &format!("nvd cpes `{term}` @{start_index}"),
                )
                .await?;
            total = resp.total;
            let received = resp.products.len() as u32;

            // Collapse per-version entries into distinct vendor/product pairs.
            for p in resp.products {
                if let Some(row) = super::model::parse_cpe(&p.cpe.cpe_name) {
                    let title = p
                        .cpe
                        .titles
                        .iter()
                        .find(|t| t.lang == "en")
                        .map(|t| t.title.clone());
                    let e = grouped
                        .entry((row.vendor, row.product))
                        .or_insert((0, title));
                    e.0 += 1;
                }
            }

            start_index += received.max(1);
            if received == 0 || start_index >= total {
                break;
            }
        }
        tracing::debug!(term, total, pairs = grouped.len(), "grouped CPE suggestions");
        let mut out: Vec<CpeSuggestion> = grouped
            .into_iter()
            .map(|((vendor, product), (entries, title))| CpeSuggestion {
                vendor,
                product,
                title,
                entries,
            })
            .collect();
        // Most dictionary entries first: that is the vendor currently shipping the product.
        out.sort_by(|a, b| {
            b.entries
                .cmp(&a.entries)
                .then_with(|| (&a.vendor, &a.product).cmp(&(&b.vendor, &b.product)))
        });
        out.truncate(limit);
        Ok(out)
    }
}

#[derive(Debug, Default)]
pub struct SyncOutcome {
    pub windows: usize,
    pub fetched: usize,
    pub new: usize,
    pub updated: usize,
    pub deltas: Vec<CveDelta>,
    /// True until [`complete_baseline`] has been called once. Callers run a suppressed
    /// pass over the stored corpus instead of enqueueing, so a fresh install does not
    /// email its whole history, then mark the baseline complete.
    pub baseline: bool,
}

/// Written to the NVD `sync_state.extra` once the first sync has reached the present and
/// its quiet pass has been recorded.
const BASELINE_DONE: &str = "baseline_complete";

/// Marks the baseline complete. The caller does this only after the suppressed pass over
/// the corpus has succeeded: setting it earlier would leave the history unrecorded if that
/// pass failed, and every later re-touch of those CVEs would then alert as `new`.
pub async fn complete_baseline(db: &Db) -> Result<()> {
    db.call(|c| queries::mark_sync_success(c, SOURCE, None, Some(BASELINE_DONE)))
        .await?;
    tracing::info!("NVD baseline complete; alerts start with the next sync");
    Ok(())
}

/// Incremental sync from the stored watermark (or `since`) up to now.
pub async fn sync(
    db: &Db,
    client: &NvdClient,
    settings: &NvdSettings,
    since: Option<Timestamp>,
) -> Result<SyncOutcome> {
    let stored = db.call(|c| queries::get_sync_state(c, SOURCE)).await?;
    let start = match since {
        Some(t) => t,
        None => match stored.cursor.as_deref() {
            Some(c) => {
                let watermark = timeutil::parse_date_or_timestamp(c)
                    .with_context(|| format!("stored NVD watermark `{c}` is unparseable"))?;
                // Step back a little: NVD is eventually consistent, so a CVE can land
                // with a lastModified just behind the instant we last queried.
                watermark
                    .checked_sub(
                        jiff::Span::new()
                            .seconds(settings.overlap.as_secs().min(i64::MAX as u64) as i64),
                    )
                    .unwrap_or(watermark)
            }
            None => timeutil::parse_start(&settings.backfill_from, Timestamp::now())
                .context("nvd.backfill_from")?,
        },
    };

    // The flag is set by the caller only after a sync reaches the present and its quiet
    // pass is recorded, so a baseline interrupted partway resumes as a baseline instead
    // of alerting on the rest of the history.
    let baseline = stored.extra.as_deref() != Some(BASELINE_DONE);
    let mut out = run_windows(db, client, start, Timestamp::now()).await?;
    out.baseline = baseline;
    Ok(out)
}

/// Walks `[start, end]` oldest-first, persisting the watermark after each completed
/// window so an interrupted run resumes instead of restarting.
pub async fn run_windows(
    db: &Db,
    client: &NvdClient,
    start: Timestamp,
    end: Timestamp,
) -> Result<SyncOutcome> {
    let windows = timeutil::windows(start, end, NVD_MAX_WINDOW_DAYS)?;
    tracing::info!(
        windows = windows.len(),
        from = %timeutil::nvd_format(start),
        to = %timeutil::nvd_format(end),
        "starting NVD sync"
    );

    let mut outcome = SyncOutcome {
        windows: windows.len(),
        ..Default::default()
    };
    // A backfill walks history that is older than the live watermark. Its windows must
    // not drag the cursor backwards, or the daemon would re-walk that span as live.
    let stored_cursor = db
        .call(|c| queries::get_sync_state(c, SOURCE))
        .await?
        .cursor;
    db.call(|c| queries::mark_sync_attempt(c, SOURCE)).await?;

    for (i, (ws, we)) in windows.iter().enumerate() {
        let cves = match client.cves_modified_between(*ws, *we).await {
            Ok(c) => c,
            Err(e) => {
                let msg = format!("{e:#}");
                db.call(move |c| queries::mark_sync_error(c, SOURCE, &msg)).await?;
                // The watermark is deliberately left where it was: the next run redoes
                // this window rather than stepping over it.
                return Err(e.context(format!(
                    "NVD window {} of {}",
                    i + 1,
                    windows.len()
                )));
            }
        };
        outcome.fetched += cves.len();

        let deltas = db
            .call(move |c| queries::upsert_cves(c, &cves))
            .await
            .context("storing an NVD window")?;
        outcome.new += deltas.iter().filter(|d| d.is_new).count();
        outcome.updated += deltas.iter().filter(|d| !d.is_new).count();
        outcome.deltas.extend(deltas);

        // Only now is this window durable, so only now may the watermark move. NVD's
        // timestamp format sorts lexicographically, so a plain comparison suffices.
        let window_end = timeutil::nvd_format(*we);
        let cursor = match &stored_cursor {
            Some(s) if s.as_str() >= window_end.as_str() => None,
            _ => Some(window_end),
        };
        db.call(move |c| queries::mark_sync_success(c, SOURCE, cursor.as_deref(), None))
            .await?;
        tracing::info!(
            window = i + 1,
            of = windows.len(),
            through = %timeutil::nvd_format(*we),
            fetched = outcome.fetched,
            "NVD window complete"
        );
    }

    tracing::info!(
        fetched = outcome.fetched,
        new = outcome.new,
        updated = outcome.updated,
        "NVD sync complete"
    );
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Settings;
    use serde_json::json;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    fn settings(server: &MockServer) -> NvdSettings {
        let mut s = Settings::default().nvd;
        s.base_url = format!("{}/rest/json", server.uri());
        // Keep the limiter out of the way of test wall-clock.
        s.rate_limit = 1000;
        s.rate_window = std::time::Duration::from_millis(1);
        s.page_size = 2;
        s
    }

    fn client(server: &MockServer) -> NvdClient {
        let mut c = NvdClient::new(super::super::http_client().unwrap(), &settings(server), None)
            .unwrap();
        c.policy = Policy {
            max_attempts: 3,
            base: std::time::Duration::from_millis(1),
            cap: std::time::Duration::from_millis(5),
        };
        c
    }

    fn cve(id: &str, score: f64, severity: &str, last_mod: &str) -> serde_json::Value {
        json!({"cve": {
            "id": id,
            "published": "2026-01-01T00:00:00.000",
            "lastModified": last_mod,
            "vulnStatus": "Analyzed",
            "descriptions": [{"lang": "en", "value": format!("A flaw in nginx, {id}")}],
            "metrics": {"cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "baseScore": score,
                    "baseSeverity": severity,
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
                }
            }]},
            "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
            "references": [{"url": format!("https://example.test/{id}"), "tags": ["Vendor Advisory"]}],
            "configurations": [{"nodes": [{"operator": "OR", "negate": false, "cpeMatch": [
                {"vulnerable": true, "criteria": "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*",
                 "matchCriteriaId": "x"}
            ]}]}]
        }})
    }

    fn page(start: u32, total: u32, items: Vec<serde_json::Value>) -> serde_json::Value {
        json!({
            "resultsPerPage": items.len(),
            "startIndex": start,
            "totalResults": total,
            "format": "NVD_CVE",
            "version": "2.0",
            "vulnerabilities": items
        })
    }

    /// Serves three pages of two, keyed on the `startIndex` the client asks for.
    struct Paginator;
    impl Respond for Paginator {
        fn respond(&self, req: &Request) -> ResponseTemplate {
            let idx: u32 = req
                .url
                .query_pairs()
                .find(|(k, _)| k == "startIndex")
                .and_then(|(_, v)| v.parse().ok())
                .unwrap_or(0);
            let body = match idx {
                0 => page(0, 5, vec![
                    cve("CVE-2026-0001", 9.8, "CRITICAL", "2026-02-01T00:00:00.000"),
                    cve("CVE-2026-0002", 7.5, "HIGH", "2026-02-01T00:00:00.000"),
                ]),
                2 => page(2, 5, vec![
                    cve("CVE-2026-0003", 5.0, "MEDIUM", "2026-02-01T00:00:00.000"),
                    cve("CVE-2026-0004", 4.0, "MEDIUM", "2026-02-01T00:00:00.000"),
                ]),
                _ => page(4, 5, vec![cve("CVE-2026-0005", 2.0, "LOW", "2026-02-01T00:00:00.000")]),
            };
            ResponseTemplate::new(200).set_body_json(body)
        }
    }

    fn ts(s: &str) -> Timestamp {
        crate::timeutil::parse_date_or_timestamp(s).unwrap()
    }

    #[tokio::test]
    async fn follows_pagination_to_the_last_page() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(Paginator)
            .mount(&server)
            .await;

        let got = client(&server)
            .cves_modified_between(ts("2026-01-01"), ts("2026-02-01"))
            .await
            .unwrap();

        assert_eq!(got.len(), 5, "all three pages must be collected");
        assert_eq!(got[0].id, "CVE-2026-0001");
        assert_eq!(got[4].id, "CVE-2026-0005");
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn an_oversized_window_is_refused_before_any_request() {
        let server = MockServer::start().await;
        // No mock is mounted: reaching the network at all would be the bug.
        let err = client(&server)
            .cves_modified_between(ts("2024-01-01"), ts("2026-01-01"))
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("120 days"), "{msg}");
        assert!(
            server.received_requests().await.unwrap().is_empty(),
            "the guard must fire client-side, not rely on NVD's 404"
        );
    }

    #[tokio::test]
    async fn a_404_is_surfaced_as_an_error_not_an_empty_page() {
        // This is the trap the whole module is shaped around: NVD answers a rejected
        // date window with a bare 404 and no body, which naive code reads as "no results".
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let err = client(&server)
            .cves_modified_between(ts("2026-01-01"), ts("2026-02-01"))
            .await
            .unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("404"), "{msg}");
        assert!(msg.contains("120 days"), "the error must name the likely cause: {msg}");
        assert_eq!(
            server.received_requests().await.unwrap().len(),
            1,
            "a 404 is a request bug, so retrying it is pointless"
        );
    }

    #[tokio::test]
    async fn throttling_backs_off_then_succeeds() {
        let server = MockServer::start().await;
        struct Throttle(AtomicUsize);
        impl Respond for Throttle {
            fn respond(&self, _: &Request) -> ResponseTemplate {
                // NVD signals throttling with 403 as often as 429.
                if self.0.fetch_add(1, Ordering::SeqCst) < 2 {
                    ResponseTemplate::new(403).insert_header("retry-after", "0")
                } else {
                    ResponseTemplate::new(200).set_body_json(page(0, 1, vec![cve(
                        "CVE-2026-9999", 9.1, "CRITICAL", "2026-02-01T00:00:00.000",
                    )]))
                }
            }
        }
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(Throttle(AtomicUsize::new(0)))
            .mount(&server)
            .await;

        let got = client(&server)
            .cves_modified_between(ts("2026-01-01"), ts("2026-02-01"))
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn the_window_params_and_norejected_flag_are_sent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .and(query_param("lastModStartDate", "2026-01-01T00:00:00.000Z"))
            .and(query_param("lastModEndDate", "2026-02-01T00:00:00.000Z"))
            .and(query_param("noRejected", ""))
            .and(query_param("resultsPerPage", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(0, 0, vec![])))
            .mount(&server)
            .await;

        let got = client(&server)
            .cves_modified_between(ts("2026-01-01"), ts("2026-02-01"))
            .await
            .unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn an_api_key_is_sent_as_the_apikey_header() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(0, 0, vec![])))
            .mount(&server)
            .await;

        let c = NvdClient::new(
            super::super::http_client().unwrap(),
            &settings(&server),
            Some(SecretString::from("test-key".to_string())),
        )
        .unwrap();
        c.cves_modified_between(ts("2026-01-01"), ts("2026-02-01"))
            .await
            .unwrap();

        let reqs = server.received_requests().await.unwrap();
        assert_eq!(
            reqs[0].headers.get("apiKey").and_then(|v| v.to_str().ok()),
            Some("test-key")
        );
    }

    #[tokio::test]
    async fn a_backfill_walks_many_windows_and_advances_the_watermark() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(Paginator)
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let out = run_windows(&db, &client(&server), ts("2026-01-01"), ts("2026-06-01"))
            .await
            .unwrap();

        assert_eq!(out.windows, 2, "152 days needs two 110-day windows");
        assert_eq!(out.fetched, 10, "5 CVEs per window");
        assert_eq!(out.new, 5, "the second window re-sees the same ids");
        assert_eq!(out.updated, 5);

        let st = db.call(|c| queries::get_sync_state(c, SOURCE)).await.unwrap();
        assert_eq!(
            st.cursor.as_deref(),
            Some("2026-06-01T00:00:00.000Z"),
            "the watermark must reach the end of the last window"
        );
        assert_eq!(db.call(|c| queries::count(c, "cves")).await.unwrap(), 5);
    }

    #[tokio::test]
    async fn a_failed_window_leaves_the_watermark_on_the_last_good_one() {
        let server = MockServer::start().await;
        // Succeed for the first window, then fail permanently. The client asks for
        // windows oldest-first, so the first request belongs to the earliest window.
        struct FailAfterFirst(AtomicUsize);
        impl Respond for FailAfterFirst {
            fn respond(&self, _: &Request) -> ResponseTemplate {
                if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
                    ResponseTemplate::new(200).set_body_json(page(0, 1, vec![cve(
                        "CVE-2026-0001", 9.8, "CRITICAL", "2026-02-01T00:00:00.000",
                    )]))
                } else {
                    ResponseTemplate::new(500)
                }
            }
        }
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(FailAfterFirst(AtomicUsize::new(0)))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let err = run_windows(&db, &client(&server), ts("2026-01-01"), ts("2026-06-01"))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("window 2 of 2"), "{err:#}");

        let st = db.call(|c| queries::get_sync_state(c, SOURCE)).await.unwrap();
        assert_eq!(
            st.cursor.as_deref(),
            Some("2026-04-21T00:00:00.000Z"),
            "the watermark stops at the end of window 1 so window 2 is retried, not skipped"
        );
        assert!(st.last_error.is_some());
        // The first window's data is durable even though the run failed.
        assert_eq!(db.call(|c| queries::count(c, "cves")).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn resuming_after_a_failure_picks_up_from_the_watermark() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(0, 0, vec![])))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        db.call(|c| {
            queries::mark_sync_success(c, SOURCE, Some("2026-05-01T00:00:00.000Z"), None)
        })
        .await
        .unwrap();

        let s = settings(&server);
        sync(&db, &client(&server), &s, None).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let start = reqs[0]
            .url
            .query_pairs()
            .find(|(k, _)| k == "lastModStartDate")
            .map(|(_, v)| v.to_string())
            .unwrap();
        // The watermark minus the 10-minute overlap, not the backfill_from date.
        assert_eq!(start, "2026-04-30T23:50:00.000Z", "overlap must be applied");
    }

    #[tokio::test]
    async fn a_cold_start_uses_backfill_from() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(0, 0, vec![])))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let mut s = settings(&server);
        s.backfill_from = "2026-09-01".into();
        sync(&db, &client(&server), &s, None).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let start = reqs[0]
            .url
            .query_pairs()
            .find(|(k, _)| k == "lastModStartDate")
            .map(|(_, v)| v.to_string())
            .unwrap();
        assert_eq!(start, "2026-09-01T00:00:00.000Z");
    }

    #[tokio::test]
    async fn a_cold_start_accepts_a_lookback() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(0, 0, vec![])))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let mut s = settings(&server);
        s.backfill_from = "30d".into();
        let before = Timestamp::now();
        sync(&db, &client(&server), &s, None).await.unwrap();

        let reqs = server.received_requests().await.unwrap();
        let start: Timestamp = reqs[0]
            .url
            .query_pairs()
            .find(|(k, _)| k == "lastModStartDate")
            .map(|(_, v)| v.to_string())
            .unwrap()
            .parse()
            .unwrap();
        let age = before.as_second() - start.as_second();
        assert!((30 * 86_400 - 5..=30 * 86_400 + 5).contains(&age), "start was {age}s back");
    }

    #[tokio::test]
    async fn only_the_first_completed_sync_is_a_baseline() {
        let server = MockServer::start().await;
        // A 404 is NVD's answer to a bad window and fails the sync outright.
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let s = settings(&server);
        assert!(sync(&db, &client(&server), &s, None).await.is_err());

        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(0, 0, vec![])))
            .mount(&server)
            .await;

        // The failed attempt never reached the present, so the next sync is still the
        // baseline. Reaching the present is not enough either: the caller's quiet pass
        // has to succeed first, and it signals that with `complete_baseline`.
        let first = sync(&db, &client(&server), &s, None).await.unwrap();
        assert!(first.baseline, "an interrupted baseline must resume as a baseline");
        let again = sync(&db, &client(&server), &s, None).await.unwrap();
        assert!(again.baseline, "only complete_baseline closes it");
        complete_baseline(&db).await.unwrap();
        let live = sync(&db, &client(&server), &s, None).await.unwrap();
        assert!(!live.baseline);
    }

    #[tokio::test]
    async fn a_backfill_never_moves_the_watermark_backwards() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(0, 0, vec![])))
            .mount(&server)
            .await;
        let db = Db::open_in_memory().unwrap();
        let s = settings(&server);
        sync(&db, &client(&server), &s, None).await.unwrap();
        let live = db.call(|c| queries::get_sync_state(c, SOURCE)).await.unwrap().cursor.unwrap();

        // Walk a year of history: four windows, every one ending before the live cursor
        // except the last, which ends now.
        let start = Timestamp::now().checked_sub(jiff::Span::new().hours(365 * 24)).unwrap();
        run_windows(&db, &client(&server), start, Timestamp::now()).await.unwrap();
        let after = db.call(|c| queries::get_sync_state(c, SOURCE)).await.unwrap().cursor.unwrap();
        assert!(after >= live, "cursor went from {live} back to {after}");
    }

    #[tokio::test]
    async fn stores_cpes_refs_cvss_and_clears_the_kev_placeholder() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(page(0, 1, vec![cve(
                "CVE-2026-0001", 9.8, "CRITICAL", "2026-02-01T00:00:00.000",
            )])))
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        // Pretend KEV got there first and created a placeholder.
        db.call(|c| {
            c.execute(
                "INSERT INTO cves (id, published, last_modified, raw, placeholder,
                                   first_seen, updated_at)
                 VALUES ('CVE-2026-0001', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z',
                         '{}', 1, 'now', 'now')",
                [],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let out = run_windows(&db, &client(&server), ts("2026-01-01"), ts("2026-02-01"))
            .await
            .unwrap();
        assert_eq!(out.new, 1, "a placeholder does not count as previously seen");

        db.call(|c| {
            let (score, sev, ver, placeholder): (f64, String, String, i64) = c.query_row(
                "SELECT cvss_score, cvss_severity, cvss_version, placeholder
                   FROM cves WHERE id = 'CVE-2026-0001'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )?;
            assert_eq!(score, 9.8);
            assert_eq!(sev, "CRITICAL");
            assert_eq!(ver, "3.1");
            assert_eq!(placeholder, 0, "NVD data must clear the placeholder flag");

            let (vendor, product): (String, String) = c.query_row(
                "SELECT vendor, product FROM cve_cpes WHERE cve_id = 'CVE-2026-0001'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            assert_eq!((vendor.as_str(), product.as_str()), ("f5", "nginx"));
            assert_eq!(queries::count(c, "cve_refs")?, 1);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn re_syncing_the_same_page_produces_updates_not_duplicates() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/rest/json/cves/2.0"))
            .respond_with(Paginator)
            .mount(&server)
            .await;

        let db = Db::open_in_memory().unwrap();
        let c = client(&server);
        let first = run_windows(&db, &c, ts("2026-01-01"), ts("2026-02-01")).await.unwrap();
        let second = run_windows(&db, &c, ts("2026-01-01"), ts("2026-02-01")).await.unwrap();

        assert_eq!(first.new, 5);
        assert_eq!(second.new, 0, "nothing is new the second time");
        assert_eq!(second.updated, 5);
        db.call(|c| {
            assert_eq!(queries::count(c, "cves")?, 5);
            assert_eq!(queries::count(c, "cve_cpes")?, 5, "CPE rows are replaced, not appended");
            assert_eq!(queries::count(c, "cve_refs")?, 5);
            Ok(())
        })
        .await
        .unwrap();
    }

    #[test]
    fn the_request_rate_is_clamped_without_an_api_key() {
        // Left unclamped, a keyless run blows through NVD's public 5/30s limit on the
        // sixth request and spends the rest of the sync in backoff.
        let mut s = Settings::default().nvd;
        s.rate_limit = 45;
        let http = super::super::http_client().unwrap();

        let keyless = NvdClient::new(http.clone(), &s, None).unwrap();
        assert_eq!(keyless.effective_rate, KEYLESS_RATE_LIMIT);

        let keyed =
            NvdClient::new(http, &s, Some(SecretString::from("k".to_string()))).unwrap();
        assert_eq!(keyed.effective_rate, 45, "a key keeps the configured rate");
    }

    #[tokio::test]
    async fn suggest_reads_every_page_before_ranking() {
        // A partial read ranks by dictionary position, not by what a vendor ships. Against
        // the live API one 500-entry page of `nginx` puts igor_sysoev first and omits f5
        // altogether, when the full set has f5:nginx on top.
        let server = MockServer::start().await;
        struct Pages;
        impl Respond for Pages {
            fn respond(&self, req: &Request) -> ResponseTemplate {
                let idx: u32 = req
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "startIndex")
                    .and_then(|(_, v)| v.parse().ok())
                    .unwrap_or(0);
                let names: Vec<&str> = if idx == 0 {
                    vec![
                        "cpe:2.3:a:igor_sysoev:nginx:0.1.27:*:*:*:*:*:*:*",
                        "cpe:2.3:a:igor_sysoev:nginx:0.3.11:*:*:*:*:*:*:*",
                    ]
                } else {
                    vec![
                        "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*",
                        "cpe:2.3:a:f5:nginx:1.26.0:*:*:*:*:*:*:*",
                        "cpe:2.3:a:f5:nginx:1.27.0:*:*:*:*:*:*:*",
                    ]
                };
                ResponseTemplate::new(200).set_body_json(json!({
                    "totalResults": 5,
                    "products": names.iter().map(|n| json!({"cpe": {"cpeName": n, "titles": []}}))
                        .collect::<Vec<_>>()
                }))
            }
        }
        Mock::given(method("GET"))
            .and(path("/rest/json/cpes/2.0"))
            .respond_with(Pages)
            .mount(&server)
            .await;

        let out = client(&server).suggest_cpes("nginx", 10).await.unwrap();
        assert_eq!(server.received_requests().await.unwrap().len(), 2, "both pages");
        assert_eq!(
            (out[0].vendor.as_str(), out[0].entries),
            ("f5", 3),
            "f5 only wins once the second page is counted"
        );
    }

    #[tokio::test]
    async fn suggest_groups_a_product_across_its_vendors() {
        let server = MockServer::start().await;
        let body = json!({"totalResults": 4, "products": [
            {"cpe": {"cpeName": "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*",
                     "titles": [{"title": "Nginx 1.25.0", "lang": "en"}]}},
            {"cpe": {"cpeName": "cpe:2.3:a:f5:nginx:1.26.0:*:*:*:*:*:*:*",
                     "titles": [{"title": "Nginx 1.26.0", "lang": "en"}]}},
            {"cpe": {"cpeName": "cpe:2.3:a:f5:nginx:1.27.0:*:*:*:*:*:*:*", "titles": []}},
            {"cpe": {"cpeName": "cpe:2.3:a:igor_sysoev:nginx:0.3.11:*:*:*:*:*:*:*",
                     "titles": [{"title": "Nginx 0.3.11", "lang": "en"}]}}
        ]});
        Mock::given(method("GET"))
            .and(path("/rest/json/cpes/2.0"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let out = client(&server).suggest_cpes("nginx", 10).await.unwrap();
        assert_eq!(out.len(), 2, "thousands of versions collapse to distinct vendors");
        // Most dictionary entries first: that is the vendor currently shipping it.
        assert_eq!((out[0].vendor.as_str(), out[0].entries), ("f5", 3));
        assert_eq!((out[1].vendor.as_str(), out[1].entries), ("igor_sysoev", 1));
    }
}
