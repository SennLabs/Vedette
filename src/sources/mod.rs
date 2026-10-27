pub mod kev;
pub mod model;
pub mod nvd;
pub mod retry;

use anyhow::Result;
use std::time::Duration;

pub const USER_AGENT: &str = concat!("vedette/", env!("CARGO_PKG_VERSION"), " (+security tooling)");

/// Default idle timeout between reads. A whole-request timeout is the wrong tool here:
/// a 2000-result NVD page takes minutes to stream, and capping total time kills a
/// download that is making steady progress. `read_timeout` instead fires only when the
/// connection actually stalls.
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(90);

pub fn http_client() -> Result<reqwest::Client> {
    http_client_with(DEFAULT_READ_TIMEOUT)
}

pub fn http_client_with(read_timeout: Duration) -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent(USER_AGENT)
        .read_timeout(read_timeout)
        .connect_timeout(Duration::from_secs(15))
        .gzip(true)
        .build()?)
}

/// Honours a `Retry-After` header in either of its two legal forms (delay-seconds or an
/// HTTP date); we only act on the numeric form, which is what NVD and Telegram send.
pub fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}
