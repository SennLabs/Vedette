//! Loose version comparison for CPE version strings.
//!
//! CPE versions are not semver. Real values from the NVD dictionary include `1.25.0`,
//! `0.3.11`, `3.1.5`, `1.0.0-beta2`, `8.0.0p1`, `*` and `-`. The `semver` crate rejects
//! many of them, so this does segment-wise comparison instead: numeric segments compare
//! numerically, alphabetic segments lexically, and a shorter version sorts below a longer
//! one that shares its prefix (`1.2` < `1.2.1`).

use anyhow::{anyhow, Result};
use std::cmp::Ordering;

/// `*` (any version) and `-` (not applicable) are CPE sentinels, not versions.
pub fn is_wildcard(v: &str) -> bool {
    matches!(v.trim(), "" | "*" | "-")
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Num(u64),
    Text(String),
}

/// A CPE/CVE version string decomposed into comparable segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LooseVersion(Vec<Segment>);

impl LooseVersion {
    pub fn parse(input: &str) -> Self {
        let mut segs = Vec::new();
        // Split on separators, then split each run into digit / non-digit groups so
        // `8.0.0p1` becomes [8, 0, 0, "p", 1] and compares sensibly against `8.0.0`.
        for part in input.split(['.', '-', '_', '+', ':', '~']) {
            if part.is_empty() {
                continue;
            }
            let mut chars = part.char_indices().peekable();
            while let Some(&(start, c)) = chars.peek() {
                let numeric = c.is_ascii_digit();
                let mut end = part.len();
                for (i, c2) in chars.by_ref() {
                    if c2.is_ascii_digit() != numeric {
                        end = i;
                        break;
                    }
                }
                let chunk = &part[start..end];
                segs.push(if numeric {
                    // A version segment wider than u64 is pathological; fall back to text.
                    match chunk.parse::<u64>() {
                        Ok(n) => Segment::Num(n),
                        Err(_) => Segment::Text(chunk.to_ascii_lowercase()),
                    }
                } else {
                    Segment::Text(chunk.to_ascii_lowercase())
                });
                if end == part.len() {
                    break;
                }
            }
        }
        LooseVersion(segs)
    }
}

impl PartialOrd for LooseVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for LooseVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        let n = self.0.len().max(other.0.len());
        for i in 0..n {
            let ord = match (self.0.get(i), other.0.get(i)) {
                (Some(Segment::Num(a)), Some(Segment::Num(b))) => a.cmp(b),
                (Some(Segment::Text(a)), Some(Segment::Text(b))) => a.cmp(b),
                // A numeric segment outranks a textual one at the same position, so
                // `1.0.0` > `1.0.0-beta` (release beats pre-release).
                (Some(Segment::Num(_)), Some(Segment::Text(_))) => Ordering::Greater,
                (Some(Segment::Text(_)), Some(Segment::Num(_))) => Ordering::Less,
                // `1.2` < `1.2.1`, but `1.2` > `1.2-beta`: a trailing numeric segment
                // adds, a trailing textual one subtracts.
                (Some(Segment::Num(_)), None) => Ordering::Greater,
                (Some(Segment::Text(_)), None) => Ordering::Less,
                (None, Some(Segment::Num(_))) => Ordering::Less,
                (None, Some(Segment::Text(_))) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            };
            if ord != Ordering::Equal {
                return ord;
            }
        }
        Ordering::Equal
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bound {
    Inclusive,
    Exclusive,
}

/// One half-open or closed interval, e.g. `>=1.24.0, <1.27.0`.
#[derive(Debug, Clone, Default)]
pub struct VersionRange {
    pub start: Option<(LooseVersion, Bound)>,
    pub end: Option<(LooseVersion, Bound)>,
    /// `== 1.2.3` pins exactly one version.
    pub exact: Option<LooseVersion>,
}

impl VersionRange {
    /// Accepts a comma-separated list of `>=`, `>`, `<=`, `<`, `=`/`==` constraints.
    pub fn parse(spec: &str) -> Result<Self> {
        let mut out = Self::default();
        for raw in spec.split(',') {
            let term = raw.trim();
            if term.is_empty() {
                continue;
            }
            let (op, rest) = if let Some(r) = term.strip_prefix(">=") {
                (">=", r)
            } else if let Some(r) = term.strip_prefix("<=") {
                ("<=", r)
            } else if let Some(r) = term.strip_prefix("==") {
                ("==", r)
            } else if let Some(r) = term.strip_prefix('>') {
                (">", r)
            } else if let Some(r) = term.strip_prefix('<') {
                ("<", r)
            } else if let Some(r) = term.strip_prefix('=') {
                ("==", r)
            } else {
                return Err(anyhow!(
                    "version constraint `{term}` must start with one of >= > <= < == ="
                ));
            };
            let v = rest.trim();
            if v.is_empty() {
                return Err(anyhow!("version constraint `{term}` has no version"));
            }
            let parsed = LooseVersion::parse(v);
            match op {
                ">=" => out.start = Some((parsed, Bound::Inclusive)),
                ">" => out.start = Some((parsed, Bound::Exclusive)),
                "<=" => out.end = Some((parsed, Bound::Inclusive)),
                "<" => out.end = Some((parsed, Bound::Exclusive)),
                "==" => out.exact = Some(parsed),
                _ => unreachable!(),
            }
        }
        if out.start.is_none() && out.end.is_none() && out.exact.is_none() {
            return Err(anyhow!("version_range `{spec}` contains no constraints"));
        }
        Ok(out)
    }

    pub fn contains(&self, v: &LooseVersion) -> bool {
        if let Some(e) = &self.exact {
            return v == e;
        }
        if let Some((lo, b)) = &self.start {
            let ord = v.cmp(lo);
            let ok = match b {
                Bound::Inclusive => ord != Ordering::Less,
                Bound::Exclusive => ord == Ordering::Greater,
            };
            if !ok {
                return false;
            }
        }
        if let Some((hi, b)) = &self.end {
            let ord = v.cmp(hi);
            let ok = match b {
                Bound::Inclusive => ord != Ordering::Greater,
                Bound::Exclusive => ord == Ordering::Less,
            };
            if !ok {
                return false;
            }
        }
        true
    }

    /// Does this range overlap the interval a CPE row describes?
    ///
    /// `cpe_version` is the literal version from the CPE criteria (or a wildcard), and the
    /// four `start`/`end` arguments are NVD's `versionStartIncluding` family.
    ///
    /// Returns `None` when the CPE side is an unbounded wildcard — the caller treats that
    /// as a permissive match with downgraded confidence, because a false positive is cheap
    /// and a missed KEV is not.
    pub fn overlaps_cpe(
        &self,
        cpe_version: Option<&str>,
        start: Option<&str>,
        start_incl: bool,
        end: Option<&str>,
        end_incl: bool,
    ) -> Option<bool> {
        // An exact version on the CPE row is the easy case.
        if let Some(v) = cpe_version.filter(|v| !is_wildcard(v)) {
            return Some(self.contains(&LooseVersion::parse(v)));
        }
        let cpe_lo = start.filter(|s| !is_wildcard(s)).map(LooseVersion::parse);
        let cpe_hi = end.filter(|s| !is_wildcard(s)).map(LooseVersion::parse);
        if cpe_lo.is_none() && cpe_hi.is_none() {
            // "all versions of this product are vulnerable" — nothing to intersect.
            return None;
        }
        // Two intervals overlap unless one ends before the other starts.
        if let (Some(hi), Some((lo, lo_b))) = (&cpe_hi, &self.start) {
            let ord = hi.cmp(lo);
            let disjoint = match (end_incl, lo_b) {
                (true, Bound::Inclusive) => ord == Ordering::Less,
                _ => ord != Ordering::Greater,
            };
            if disjoint {
                return Some(false);
            }
        }
        if let (Some(lo), Some((hi, hi_b))) = (&cpe_lo, &self.end) {
            let ord = lo.cmp(hi);
            let disjoint = match (start_incl, hi_b) {
                (true, Bound::Inclusive) => ord == Ordering::Greater,
                _ => ord != Ordering::Less,
            };
            if disjoint {
                return Some(false);
            }
        }
        if let Some(exact) = &self.exact {
            if let Some(lo) = &cpe_lo {
                let ord = exact.cmp(lo);
                if ord == Ordering::Less || (!start_incl && ord == Ordering::Equal) {
                    return Some(false);
                }
            }
            if let Some(hi) = &cpe_hi {
                let ord = exact.cmp(hi);
                if ord == Ordering::Greater || (!end_incl && ord == Ordering::Equal) {
                    return Some(false);
                }
            }
        }
        Some(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> LooseVersion {
        LooseVersion::parse(s)
    }

    #[test]
    fn orders_plain_numeric_versions() {
        assert!(v("1.25.0") > v("1.24.9"));
        assert!(v("0.3.11") > v("0.3.2"), "numeric, not lexical");
        assert!(v("3.1.5") < v("3.10.0"));
        assert_eq!(v("1.2.3"), v("1.2.3"));
    }

    #[test]
    fn shorter_prefix_sorts_below_longer() {
        assert!(v("1.2") < v("1.2.1"));
        assert!(v("1.2.0") > v("1.2"));
    }

    #[test]
    fn release_outranks_prerelease() {
        assert!(v("1.0.0") > v("1.0.0-beta2"));
        assert!(v("1.0.0-beta2") > v("1.0.0-alpha9"));
        assert!(v("1.0.0-beta10") > v("1.0.0-beta2"), "beta10 > beta2");
    }

    #[test]
    fn handles_embedded_alpha_segments() {
        assert!(v("8.0.0p1") > v("8.0.0"));
        assert!(v("8.0.0p2") > v("8.0.0p1"));
    }

    #[test]
    fn malformed_input_does_not_panic() {
        for s in ["", "*", "-", "...", "99999999999999999999999999", "???"] {
            let _ = v(s);
        }
        assert!(is_wildcard("*") && is_wildcard("-") && is_wildcard(""));
        assert!(!is_wildcard("1.0"));
    }

    #[test]
    fn parses_and_applies_ranges() {
        let r = VersionRange::parse(">=1.24.0, <1.27.0").unwrap();
        assert!(r.contains(&v("1.25.3")));
        assert!(r.contains(&v("1.24.0")));
        assert!(!r.contains(&v("1.27.0")));
        assert!(!r.contains(&v("1.23.9")));
    }

    #[test]
    fn rejects_malformed_ranges() {
        assert!(VersionRange::parse("1.2.3").is_err(), "needs an operator");
        assert!(VersionRange::parse(">=").is_err());
        assert!(VersionRange::parse("").is_err());
    }

    #[test]
    fn exact_version_on_cpe_row() {
        let r = VersionRange::parse(">=1.24.0, <1.27.0").unwrap();
        assert_eq!(r.overlaps_cpe(Some("1.25.0"), None, false, None, false), Some(true));
        assert_eq!(r.overlaps_cpe(Some("1.20.0"), None, false, None, false), Some(false));
    }

    #[test]
    fn unbounded_cpe_wildcard_is_inconclusive() {
        let r = VersionRange::parse(">=1.24.0").unwrap();
        // "every version vulnerable" — caller must match permissively as `review`.
        assert_eq!(r.overlaps_cpe(Some("*"), None, false, None, false), None);
    }

    #[test]
    fn intersects_ranged_cpe_rows() {
        let r = VersionRange::parse(">=1.24.0, <1.27.0").unwrap();
        // CPE says [1.25.0, 1.26.0) -> overlaps.
        assert_eq!(
            r.overlaps_cpe(Some("*"), Some("1.25.0"), true, Some("1.26.0"), false),
            Some(true)
        );
        // CPE says [1.0.0, 1.10.0) -> entirely below the watch range.
        assert_eq!(
            r.overlaps_cpe(Some("*"), Some("1.0.0"), true, Some("1.10.0"), false),
            Some(false)
        );
        // CPE says >=2.0.0 -> entirely above.
        assert_eq!(
            r.overlaps_cpe(Some("*"), Some("2.0.0"), true, None, false),
            Some(false)
        );
        // Touching endpoints: CPE <=1.24.0 and watch >=1.24.0 share exactly 1.24.0.
        assert_eq!(
            r.overlaps_cpe(Some("*"), None, false, Some("1.24.0"), true),
            Some(true)
        );
        // CPE <1.24.0 (exclusive) and watch >=1.24.0 are disjoint.
        assert_eq!(
            r.overlaps_cpe(Some("*"), None, false, Some("1.24.0"), false),
            Some(false)
        );
    }
}
