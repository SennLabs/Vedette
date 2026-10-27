//! Timestamp parsing and the NVD date format.

use anyhow::{anyhow, Context, Result};
use jiff::{civil, tz::TimeZone, Timestamp, ToSpan};
use std::time::Duration;

/// NVD wants `yyyy-MM-ddTHH:mm:ss.SSS` with an offset or `Z`.
pub fn nvd_format(ts: Timestamp) -> String {
    ts.strftime("%Y-%m-%dT%H:%M:%S.000Z").to_string()
}

/// Accepts `YYYY-MM-DD` (treated as UTC midnight) or a full RFC 3339 timestamp.
pub fn parse_date_or_timestamp(input: &str) -> Result<Timestamp> {
    let s = input.trim();
    if let Ok(date) = s.parse::<civil::Date>() {
        return Ok(date
            .to_zoned(TimeZone::UTC)
            .with_context(|| format!("converting date `{s}` to UTC"))?
            .timestamp());
    }
    s.parse::<Timestamp>()
        .with_context(|| format!("`{s}` is not a YYYY-MM-DD date or an RFC 3339 timestamp"))
}

/// Accepts a lookback such as `90d` (counted back from `now`), a `YYYY-MM-DD` date or an
/// RFC 3339 timestamp. A lookback keeps a default like `nvd.backfill_from` from drifting:
/// a fixed date makes every new install's first sync a little larger than the last.
pub fn parse_start(input: &str, now: Timestamp) -> Result<Timestamp> {
    if let Ok(back) = humantime::parse_duration(input.trim()) {
        if back.is_zero() {
            return Err(anyhow!("lookback `{}` is zero; it would fetch nothing", input.trim()));
        }
        let secs = i64::try_from(back.as_secs()).context("lookback is too large")?;
        // `Span::seconds` panics past jiff's bounds; `try_seconds` reports it instead.
        let span = jiff::Span::new()
            .try_seconds(secs)
            .with_context(|| format!("lookback `{}` is too large", input.trim()))?;
        return now
            .checked_sub(span)
            .with_context(|| format!("lookback `{input}` reaches before the earliest date"));
    }
    parse_date_or_timestamp(input).map_err(|_| {
        anyhow!(
            "`{}` is not a lookback like `90d`, a YYYY-MM-DD date or an RFC 3339 timestamp",
            input.trim()
        )
    })
}

/// Parses a relative window such as `90d`, `12h` or `30m`.
pub fn parse_lookback(spec: &str) -> Result<Duration> {
    humantime::parse_duration(spec.trim())
        .with_context(|| format!("`{spec}` is not a duration like `90d`, `12h` or `30m`"))
}

/// Splits `[start, end]` into consecutive windows no longer than `max_days`.
///
/// NVD rejects a `lastModStartDate`/`lastModEndDate` span wider than 120 days with a bare
/// **404** and no error body, which reads exactly like "no results". Chunking here is the
/// only thing standing between a backfill and silently importing nothing.
pub fn windows(start: Timestamp, end: Timestamp, max_days: i64) -> Result<Vec<(Timestamp, Timestamp)>> {
    if max_days <= 0 {
        return Err(anyhow!("window size must be at least one day"));
    }
    if start > end {
        return Err(anyhow!(
            "start {} is after end {}",
            nvd_format(start),
            nvd_format(end)
        ));
    }
    let mut out = Vec::new();
    let mut cursor = start;
    while cursor < end {
        // Hours, not days: jiff refuses to add non-uniform units such as days to a bare
        // Timestamp, and swallowing that error would collapse the whole span into one
        // oversized window that NVD answers with a bare 404.
        let next = cursor
            .checked_add((max_days * 24).hours())
            .with_context(|| {
                format!("advancing {} by {max_days} days overflowed", nvd_format(cursor))
            })?
            .min(end);
        out.push((cursor, next));
        cursor = next;
    }
    // A zero-length span still deserves one request, so an idle poll re-checks the tail.
    if out.is_empty() {
        out.push((start, end));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: &str) -> Timestamp {
        parse_date_or_timestamp(s).unwrap()
    }

    #[test]
    fn formats_for_nvd() {
        let t = ts("2026-10-26T12:34:56Z");
        assert_eq!(nvd_format(t), "2026-10-26T12:34:56.000Z");
    }

    #[test]
    fn parses_both_accepted_spellings() {
        assert_eq!(nvd_format(ts("2024-01-01")), "2024-01-01T00:00:00.000Z");
        assert_eq!(
            nvd_format(ts("2024-01-01T05:00:00Z")),
            "2024-01-01T05:00:00.000Z"
        );
        assert!(parse_date_or_timestamp("not-a-date").is_err());
        assert!(parse_date_or_timestamp("2024-13-45").is_err());
    }

    #[test]
    fn parses_lookbacks() {
        assert_eq!(parse_lookback("90d").unwrap(), Duration::from_secs(90 * 86400));
        assert_eq!(parse_lookback("30m").unwrap(), Duration::from_secs(1800));
        assert!(parse_lookback("soon").is_err());
    }

    #[test]
    fn a_start_is_a_lookback_or_a_date() {
        let now = ts("2026-10-27T12:00:00Z");
        assert_eq!(parse_start("90d", now).unwrap(), ts("2026-07-29T12:00:00Z"));
        assert_eq!(parse_start(" 12h ", now).unwrap(), ts("2026-10-27T00:00:00Z"));
        assert_eq!(parse_start("2024-01-01", now).unwrap(), ts("2024-01-01"));
        assert_eq!(
            parse_start("2026-10-01T06:00:00Z", now).unwrap(),
            ts("2026-10-01T06:00:00Z")
        );
        let err = parse_start("last quarter", now).unwrap_err().to_string();
        assert!(err.contains("lookback") && err.contains("YYYY-MM-DD"), "{err}");
        // A zero window fetches nothing and would close a baseline on an empty corpus.
        assert!(parse_start("0d", now).is_err());
        // Past jiff's span bounds: an error, not a panic in the daemon's first cycle.
        assert!(parse_start("25000y", now).unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn a_short_span_is_one_window() {
        let w = windows(ts("2026-01-01"), ts("2026-02-01"), 110).unwrap();
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].0, ts("2026-01-01"));
        assert_eq!(w[0].1, ts("2026-02-01"));
    }

    #[test]
    fn no_window_can_exceed_the_nvd_cap() {
        // Two and a half years, the shape of a real cold-start backfill.
        let w = windows(ts("2024-01-01"), ts("2026-07-01"), 110).unwrap();
        assert!(w.len() > 8, "expected many windows, got {}", w.len());
        for (a, b) in &w {
            let days = (b.as_second() - a.as_second()) / 86_400;
            assert!(days <= 120, "window of {days} days exceeds NVD's hard cap");
            assert!(days <= 110, "window of {days} days exceeds the configured max");
        }
    }

    #[test]
    fn windows_are_contiguous_and_cover_the_whole_span() {
        let (start, end) = (ts("2024-01-01"), ts("2026-07-01"));
        let w = windows(start, end, 110).unwrap();
        assert_eq!(w.first().unwrap().0, start);
        assert_eq!(w.last().unwrap().1, end, "the tail must reach the end exactly");
        for pair in w.windows(2) {
            assert_eq!(pair[0].1, pair[1].0, "a gap would silently drop CVEs");
        }
    }

    #[test]
    fn an_empty_span_still_produces_one_request() {
        let t = ts("2026-01-01");
        assert_eq!(windows(t, t, 110).unwrap().len(), 1);
    }

    #[test]
    fn a_reversed_span_is_rejected() {
        assert!(windows(ts("2026-02-01"), ts("2026-01-01"), 110).is_err());
    }
}
