//! Alert rendering. One digest per batch, in HTML, plain text and the short forms the
//! push channels need.

use crate::events::EventKind;
use crate::pipeline::Alert;
use askama::Template;

/// Askama filters.
///
/// askama 0.16 requires each custom filter to carry `#[askama::filter_fn]` and to take a
/// `&dyn askama::Values` environment argument after the value; without the attribute the
/// derive looks for a *type* of that name and fails with "expected type, found function".
///
/// The value parameter is generic rather than `&dyn Display`: a template expression that
/// yields `&'static str` (such as `a.event.kind.as_str()`) cannot coerce to `&dyn Display`,
/// because `str` is unsized.
pub mod filters {
    #[askama::filter_fn]
    pub fn truncate_chars<S: std::fmt::Display>(
        s: S,
        _: &dyn askama::Values,
        max: usize,
    ) -> askama::Result<String> {
        let s = s.to_string();
        // Count characters, not bytes: slicing a multi-byte sequence would panic.
        if s.chars().count() <= max {
            return Ok(s);
        }
        let mut out: String = s.chars().take(max).collect();
        out.push('\u{2026}');
        Ok(out)
    }

    #[askama::filter_fn]
    pub fn severity_colour<S: std::fmt::Display>(
        s: S,
        _: &dyn askama::Values,
    ) -> askama::Result<String> {
        Ok(match s.to_string().to_ascii_uppercase().as_str() {
            "CRITICAL" => "#b91c1c",
            "HIGH" => "#d9480f",
            "MEDIUM" => "#b7791f",
            "LOW" => "#2b6cb0",
            _ => "#616e7c",
        }
        .to_string())
    }

    /// Takes the event kind as a string rather than the whole `Alert`: a filter receives
    /// its input as `&dyn Display`, so the template passes `a.event.kind.as_str()`.
    #[askama::filter_fn]
    pub fn event_colour<S: std::fmt::Display>(
        kind: S,
        _: &dyn askama::Values,
    ) -> askama::Result<String> {
        Ok(match kind.to_string().as_str() {
            "kev_added" => "#b91c1c",
            "exploit_ref" => "#d9480f",
            "score_increase" | "severity_threshold" => "#b7791f",
            _ => "#1f6feb",
        }
        .to_string())
    }
}

#[derive(Template)]
#[template(path = "alert.html")]
struct HtmlTemplate<'a> {
    heading: &'a str,
    alerts: &'a [Alert],
}

#[derive(Template)]
#[template(path = "alert.txt")]
struct TextTemplate<'a> {
    heading: &'a str,
    rule: &'a str,
    alerts: &'a [Alert],
}

/// A one-line summary used as the mail subject and the push notification title.
pub fn heading(batch: &[Alert]) -> String {
    let urgent = batch.iter().filter(|a| a.urgent).count();
    let kev = batch
        .iter()
        .filter(|a| a.event.kind == EventKind::KevAdded)
        .count();

    if batch.len() == 1 {
        let a = &batch[0];
        let sev = a.severity.as_deref().unwrap_or("unscored");
        return match a.event.kind {
            EventKind::KevAdded => format!("[KEV] {} — {} ({})", a.cve_id, a.watch, sev),
            _ => format!("[{}] {} {} — {}", sev, a.cve_id, a.watch, a.event.kind.as_str()),
        };
    }

    let mut s = format!("{} CVE alerts", batch.len());
    if kev > 0 {
        s = format!("{s} — {kev} newly exploited (KEV)");
    } else if urgent > 0 {
        s = format!("{s} — {urgent} urgent");
    }
    // Name the watches so the subject says something even when collapsed in a mail list.
    let mut watches: Vec<&str> = batch.iter().map(|a| a.watch.as_str()).collect();
    watches.sort_unstable();
    watches.dedup();
    if watches.len() <= 3 {
        s = format!("{s} [{}]", watches.join(", "));
    }
    s
}

pub fn html(batch: &[Alert]) -> anyhow::Result<String> {
    Ok(HtmlTemplate {
        heading: &heading(batch),
        alerts: batch,
    }
    .render()?)
}

pub fn text(batch: &[Alert]) -> anyhow::Result<String> {
    let h = heading(batch);
    Ok(TextTemplate {
        heading: &h,
        rule: &"=".repeat(h.chars().count().min(72)),
        alerts: batch,
    }
    .render()?)
}

/// Flattens a string to visible ASCII so it is legal in an HTTP header value.
///
/// Header values must be visible ASCII. `heading()` contains an em dash, which reqwest
/// will happily put on the wire as raw UTF-8 bytes and ntfy then mangles. Common
/// punctuation is transliterated rather than dropped so the title still reads properly.
pub fn ascii_header(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\u{2014}' | '\u{2013}' => out.push('-'),      // em dash, en dash
            '\u{2026}' => out.push_str("..."),             // ellipsis
            '\u{2018}' | '\u{2019}' => out.push('\''),     // curly single quotes
            '\u{201C}' | '\u{201D}' => out.push('"'),      // curly double quotes
            '\u{00A0}' => out.push(' '),                   // non-breaking space
            c if c.is_ascii_graphic() || c == ' ' => out.push(c),
            // Anything else (including emoji and control characters) is dropped rather
            // than risking a rejected or corrupted header.
            _ => {}
        }
    }
    out.trim().to_string()
}

/// Markdown digest for the push and chat channels, which have tight length limits.
pub fn markdown(batch: &[Alert], max_items: usize) -> String {
    let mut out = String::new();
    for a in batch.iter().take(max_items) {
        let sev = a.severity.as_deref().unwrap_or("unscored");
        out.push_str(&format!(
            "*{}* ({}) — {}\n{}\n{}\n\n",
            a.cve_id, sev, a.watch, a.event.detail, a.url
        ));
    }
    if batch.len() > max_items {
        out.push_str(&format!("...and {} more\n", batch.len() - max_items));
    }
    out
}

/// Splits text into chunks of at most `limit` characters, breaking on line boundaries.
///
/// Telegram rejects a message over 4096 characters outright, so a long digest has to be
/// split rather than truncated.
pub fn chunk(text: &str, limit: usize) -> Vec<String> {
    if text.chars().count() <= limit {
        return vec![text.to_string()];
    }
    let mut out = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        // A single line longer than the limit has to be cut mid-line; nothing else to do.
        if line.chars().count() >= limit {
            if !cur.is_empty() {
                out.push(std::mem::take(&mut cur));
            }
            let mut rest: Vec<char> = line.chars().collect();
            while !rest.is_empty() {
                let take = rest.len().min(limit);
                out.push(rest.drain(..take).collect());
            }
            continue;
        }
        if cur.chars().count() + line.chars().count() + 1 > limit {
            out.push(std::mem::take(&mut cur));
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::events::Event;

    pub fn alert(cve: &str, watch: &str, kind: EventKind, severity: Option<&str>) -> Alert {
        Alert {
            watch: watch.into(),
            cve_id: cve.into(),
            event: Event {
                kind,
                detail: "something changed".into(),
                fingerprint: "fp".into(),
            },
            confidence: "high".into(),
            match_kind: "cpe".into(),
            evidence: "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*".into(),
            severity: severity.map(str::to_string),
            score: Some(9.8),
            description: Some("A buffer overflow in nginx allows remote code execution".into()),
            in_kev: kind == EventKind::KevAdded,
            kev_due_date: Some("2026-11-10".into()),
            kev_ransomware: true,
            urgent: kind.is_urgent(),
            url: format!("https://nvd.nist.gov/vuln/detail/{cve}"),
        }
    }

    #[test]
    fn a_single_alert_subject_names_the_cve() {
        let b = vec![alert("CVE-2026-1", "nginx", EventKind::New, Some("CRITICAL"))];
        let h = heading(&b);
        assert!(h.contains("CVE-2026-1"), "{h}");
        assert!(h.contains("CRITICAL"), "{h}");
    }

    #[test]
    fn a_kev_subject_leads_with_kev() {
        let b = vec![alert("CVE-2026-2", "nginx", EventKind::KevAdded, Some("HIGH"))];
        assert!(heading(&b).starts_with("[KEV]"), "{}", heading(&b));
    }

    #[test]
    fn a_digest_subject_counts_and_names_watches() {
        let b = vec![
            alert("CVE-2026-1", "nginx", EventKind::New, Some("HIGH")),
            alert("CVE-2026-2", "wordpress", EventKind::KevAdded, Some("HIGH")),
        ];
        let h = heading(&b);
        assert!(h.contains("2 CVE alerts"), "{h}");
        assert!(h.contains("1 newly exploited"), "{h}");
        assert!(h.contains("nginx") && h.contains("wordpress"), "{h}");
    }

    #[test]
    fn html_renders_every_alert_and_escapes_markup() {
        let mut b = vec![
            alert("CVE-2026-1", "nginx", EventKind::New, Some("CRITICAL")),
            alert("CVE-2026-2", "wordpress", EventKind::KevAdded, None),
        ];
        b[0].description = Some("<script>alert(1)</script> & co".into());
        let out = html(&b).unwrap();
        assert!(out.contains("CVE-2026-1") && out.contains("CVE-2026-2"));
        assert!(out.contains("CISA KEV catalog"), "the KEV banner must render");
        assert!(
            !out.contains("<script>"),
            "a CVE description comes from upstream and must be escaped"
        );
        assert!(out.contains("&#60;script&#62;") || out.contains("&lt;script&gt;"), "{out}");
    }

    #[test]
    fn text_renders_without_markup() {
        let b = vec![alert("CVE-2026-1", "nginx", EventKind::KevAdded, Some("HIGH"))];
        let out = text(&b).unwrap();
        assert!(out.contains("CVE-2026-1"));
        assert!(out.contains("actively exploited"));
        assert!(!out.contains('<'), "the text part must carry no markup: {out}");
    }

    #[test]
    fn long_descriptions_are_truncated_on_a_char_boundary() {
        let mut b = vec![alert("CVE-2026-1", "nginx", EventKind::New, Some("HIGH"))];
        // Multi-byte characters: truncating by bytes here would panic.
        b[0].description = Some("é".repeat(1_000));
        let out = text(&b).unwrap();
        assert!(out.contains('…'));
    }

    #[test]
    fn ascii_header_transliterates_rather_than_dropping() {
        // The heading contains an em dash, which is not legal in an HTTP header value.
        let h = heading(&[alert("CVE-2026-1", "nginx", EventKind::KevAdded, Some("CRITICAL"))]);
        assert!(h.contains('\u{2014}'), "fixture must contain an em dash");
        let a = ascii_header(&h);
        assert!(a.is_ascii(), "{a}");
        assert!(a.contains("- nginx"), "the dash must survive as ASCII: {a}");
        assert!(a.contains("CVE-2026-1"));
    }

    #[test]
    fn ascii_header_handles_the_punctuation_we_emit() {
        assert_eq!(ascii_header("a\u{2026}b"), "a...b");
        assert_eq!(ascii_header("\u{201C}q\u{201D}"), "\"q\"");
        assert_eq!(ascii_header("it\u{2019}s"), "it's");
        assert_eq!(ascii_header("  pad\u{00A0}ded  "), "pad ded");
        // Emoji and control characters are dropped outright.
        assert_eq!(ascii_header("ok\u{1F6A8}\u{7}"), "ok");
    }

    #[test]
    fn chunking_respects_the_telegram_limit() {
        let b: Vec<Alert> = (0..200)
            .map(|i| alert(&format!("CVE-2026-{i}"), "nginx", EventKind::New, Some("HIGH")))
            .collect();
        let md = markdown(&b, 200);
        assert!(md.chars().count() > 4096, "the fixture must exceed the limit");
        let chunks = chunk(&md, 4096);
        assert!(chunks.len() > 1);
        for c in &chunks {
            assert!(c.chars().count() <= 4096, "chunk of {} chars", c.chars().count());
        }
        // Nothing may be lost in the split.
        assert!(chunks.concat().contains("CVE-2026-199"));
    }

    #[test]
    fn a_short_message_is_a_single_chunk() {
        assert_eq!(chunk("hello\nworld", 4096).len(), 1);
    }

    #[test]
    fn an_overlong_single_line_is_split_rather_than_dropped() {
        let line = "x".repeat(10_000);
        let chunks = chunk(&line, 4096);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks.concat().chars().count(), 10_000);
    }

    #[test]
    fn markdown_caps_the_item_count() {
        let b: Vec<Alert> = (0..50)
            .map(|i| alert(&format!("CVE-2026-{i}"), "nginx", EventKind::New, Some("HIGH")))
            .collect();
        let md = markdown(&b, 5);
        assert!(md.contains("and 45 more"), "{md}");
    }
}
