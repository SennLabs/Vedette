//! Watch evaluation.
//!
//! A CVE is tested against a watch three ways, strongest evidence first:
//!
//! 1. **CPE** — NVD's structured `configurations` data, matched on vendor/product and
//!    optionally intersected with a version range. High confidence.
//! 2. **KEV** — the CVE is in the CISA catalog and its `vendorProject`/`product` text
//!    matches the watch. High confidence, and exempt from the severity floor.
//! 3. **Keyword** — text match on description, CPE strings, KEV product or references.
//!    Flagged `review`, because this is the loose pass.
//!
//! The keyword pass is not a convenience. A freshly published CVE sits in
//! `Awaiting Analysis` with no CPE data whatsoever for days, which is exactly the window
//! where a notification is worth most. Without it, CPE-only matching is blind there.

pub mod keyword;
pub mod version;

use crate::config::{Severity, Watch};
use crate::matcher::version::VersionRange;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Text-only evidence; worth a look but not proof.
    Review,
    /// Structured evidence from NVD's CPE data or the KEV catalog.
    High,
}

impl Confidence {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Review => "review",
            Self::High => "high",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchKind {
    Cpe,
    Kev,
    Keyword,
}

impl MatchKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpe => "cpe",
            Self::Kev => "kev",
            Self::Keyword => "keyword",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Match {
    pub kind: MatchKind,
    pub confidence: Confidence,
    /// What actually matched: a CPE criteria string, a KEV product, or a keyword.
    pub evidence: String,
}

/// Everything the matcher needs about one CVE. Assembled by `db::queries::candidate`.
#[derive(Debug, Clone, Default)]
pub struct Candidate {
    pub id: String,
    pub description: Option<String>,
    pub severity: Option<Severity>,
    pub cpes: Vec<CandidateCpe>,
    pub reference_urls: Vec<String>,
    pub kev: Option<CandidateKev>,
}

#[derive(Debug, Clone, Default)]
pub struct CandidateCpe {
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
    pub criteria: String,
    pub ver_start: Option<String>,
    pub ver_start_incl: bool,
    pub ver_end: Option<String>,
    pub ver_end_incl: bool,
}

#[derive(Debug, Clone, Default)]
pub struct CandidateKev {
    pub vendor_project: Option<String>,
    pub product: Option<String>,
    pub vulnerability_name: Option<String>,
    pub due_date: Option<String>,
    pub known_ransomware: bool,
}

/// A watch with its regexes and version ranges compiled once.
///
/// This exists because compiling per CVE is ruinous: a poll cycle evaluates thousands of
/// CVEs against the same handful of watches, and building the regex set and parsing every
/// `version_range` inside the per-CVE path turned a 5000-CVE pass into minutes of regex
/// compilation.
pub struct CompiledWatch<'a> {
    pub watch: &'a Watch,
    keywords: keyword::KeywordMatcher<'a>,
    /// Parsed `version_range` per `[[watch.cpe]]`, index-aligned with `watch.cpe`.
    ranges: Vec<Option<VersionRange>>,
    /// Lowercased vendor/product per selector, also index-aligned.
    selectors: Vec<(String, String)>,
}

impl<'a> CompiledWatch<'a> {
    pub fn new(watch: &'a Watch) -> Result<Self> {
        let mut ranges = Vec::with_capacity(watch.cpe.len());
        let mut selectors = Vec::with_capacity(watch.cpe.len());
        for sel in &watch.cpe {
            ranges.push(
                sel.version_range
                    .as_deref()
                    .map(VersionRange::parse)
                    .transpose()?,
            );
            selectors.push((
                sel.vendor.to_ascii_lowercase(),
                sel.product.to_ascii_lowercase(),
            ));
        }
        Ok(Self {
            watch,
            keywords: keyword::KeywordMatcher::compile(&watch.keywords)?,
            ranges,
            selectors,
        })
    }

    /// Compiles a whole watch list, reporting which watch failed.
    pub fn compile_all(watches: &'a [Watch]) -> Result<Vec<Self>> {
        watches
            .iter()
            .map(|w| {
                Self::new(w).with_context(|| format!("compiling watch `{}`", w.name))
            })
            .collect()
    }

    /// Evaluates one CVE against this watch.
    ///
    /// Returns the strongest match, or `None` when the watch does not apply. Exclusions
    /// are absolute: a `keywords.none` hit vetoes the CVE even when the CPE evidence is
    /// exact, because that list exists precisely to kill a known false-positive source.
    pub fn evaluate(&self, c: &Candidate) -> Option<Match> {
        if !self.watch.enabled {
            return None;
        }
        if self.keywords.is_excluded(c) {
            return None;
        }

        let mut best: Option<Match> = None;
        let mut consider = |m: Match| {
            let better = match &best {
                None => true,
                Some(cur) => m.confidence > cur.confidence,
            };
            if better {
                best = Some(m);
            }
        };

        // 1. CPE pass.
        for (i, (want_vendor, want_product)) in self.selectors.iter().enumerate() {
            let range = &self.ranges[i];
            for cpe in &c.cpes {
                if &cpe.vendor != want_vendor || &cpe.product != want_product {
                    continue;
                }
                match range {
                    None => consider(Match {
                        kind: MatchKind::Cpe,
                        confidence: Confidence::High,
                        evidence: cpe.criteria.clone(),
                    }),
                    Some(r) => match r.overlaps_cpe(
                        cpe.version.as_deref(),
                        cpe.ver_start.as_deref(),
                        cpe.ver_start_incl,
                        cpe.ver_end.as_deref(),
                        cpe.ver_end_incl,
                    ) {
                        Some(true) => consider(Match {
                            kind: MatchKind::Cpe,
                            confidence: Confidence::High,
                            evidence: cpe.criteria.clone(),
                        }),
                        Some(false) => {}
                        // The CPE row says "all versions", so there is nothing to
                        // intersect. Match permissively but downgrade: a false positive
                        // is cheap, a missed KEV is not.
                        None => consider(Match {
                            kind: MatchKind::Cpe,
                            confidence: Confidence::Review,
                            evidence: format!("{} (version unbounded)", cpe.criteria),
                        }),
                    },
                }
            }
        }

        // 2. KEV pass: the catalog's own vendor/product text, which exists even when NVD
        //    has not produced CPE data yet.
        if let Some(kev) = &c.kev {
            let haystacks: Vec<String> = [&kev.vendor_project, &kev.product]
                .into_iter()
                .flatten()
                .map(|s| s.to_ascii_lowercase().replace('_', " "))
                .collect();
            for (_, product) in &self.selectors {
                // Only the product name counts here. Matching on the vendor as an
                // alternative is far too loose: a watch for `f5:nginx` would then fire on
                // every F5 KEV entry, and "F5 / BIG-IP" has nothing to do with nginx.
                if product.is_empty() {
                    continue;
                }
                let product = product.replace('_', " ");
                if haystacks.iter().any(|h| h.contains(&product)) {
                    consider(Match {
                        kind: MatchKind::Kev,
                        confidence: Confidence::High,
                        evidence: format!(
                            "KEV {} / {}",
                            kev.vendor_project.as_deref().unwrap_or("?"),
                            kev.product.as_deref().unwrap_or("?")
                        ),
                    });
                }
            }
            if let Some(term) = self.keywords.first_hit_in_kev(kev) {
                consider(Match {
                    kind: MatchKind::Kev,
                    confidence: Confidence::High,
                    evidence: format!("KEV text matched `{term}`"),
                });
            }
        }

        // 3. Keyword pass.
        if let Some((term, field)) = self.keywords.first_hit(c) {
            consider(Match {
                kind: MatchKind::Keyword,
                confidence: Confidence::Review,
                evidence: format!("`{term}` in {field}"),
            });
        }

        let m = best?;

        // 4. Severity floor. A KEV entry is being exploited right now, so a low CVSS score
        //    is not a reason to stay quiet about it.
        if let Some(floor) = self.watch.severity_min {
            if m.kind != MatchKind::Kev && c.kev.is_none() {
                match c.severity {
                    Some(s) if s >= floor => {}
                    // An unscored CVE is usually one NVD has not analysed yet. Dropping it
                    // would hide brand-new vulnerabilities, so it passes as `review`.
                    None => {
                        return Some(Match {
                            confidence: Confidence::Review,
                            evidence: format!("{} (unscored)", m.evidence),
                            ..m
                        })
                    }
                    Some(_) => return None,
                }
            }
        }
        Some(m)
    }
}

/// Convenience wrapper that compiles the watch and evaluates one CVE.
///
/// Fine for a one-off; use [`CompiledWatch`] when evaluating many CVEs against the same
/// watch, which is every hot path.
pub fn evaluate(watch: &Watch, c: &Candidate) -> Result<Option<Match>> {
    Ok(CompiledWatch::new(watch)?.evaluate(c))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::WatchFile;

    fn watch(toml_src: &str) -> Watch {
        let f: WatchFile = toml::from_str(toml_src).unwrap();
        f.validate().unwrap();
        f.watches.into_iter().next().unwrap()
    }

    fn nginx_watch() -> Watch {
        watch(
            r#"
            [[watch]]
            name = "nginx"
            severity_min = "medium"
              [[watch.cpe]]
              vendor = "f5"
              product = "nginx"
              [watch.keywords]
              any = ["nginx", "njs"]
              none = ["nginx proxy manager"]
              fields = ["description", "cpe", "kev_product", "refs"]
            "#,
        )
    }

    fn cpe(vendor: &str, product: &str, version: Option<&str>) -> CandidateCpe {
        CandidateCpe {
            vendor: vendor.into(),
            product: product.into(),
            version: version.map(str::to_string),
            criteria: format!(
                "cpe:2.3:a:{vendor}:{product}:{}:*:*:*:*:*:*:*",
                version.unwrap_or("*")
            ),
            ..Default::default()
        }
    }

    fn candidate(id: &str) -> Candidate {
        Candidate {
            id: id.into(),
            severity: Some(Severity::High),
            ..Default::default()
        }
    }

    #[test]
    fn a_cpe_hit_is_high_confidence() {
        let mut c = candidate("CVE-1");
        c.cpes = vec![cpe("f5", "nginx", Some("1.25.0"))];
        let m = evaluate(&nginx_watch(), &c).unwrap().unwrap();
        assert_eq!(m.kind, MatchKind::Cpe);
        assert_eq!(m.confidence, Confidence::High);
        assert!(m.evidence.contains("f5:nginx"));
    }

    #[test]
    fn a_description_only_hit_is_review() {
        // The shape of a brand-new CVE: NVD has not assigned any CPE data yet.
        let mut c = candidate("CVE-2");
        c.description = Some("A buffer overflow in nginx 1.25 allows RCE".into());
        let m = evaluate(&nginx_watch(), &c).unwrap().unwrap();
        assert_eq!(m.kind, MatchKind::Keyword);
        assert_eq!(m.confidence, Confidence::Review);
    }

    #[test]
    fn a_cpe_hit_outranks_a_keyword_hit_on_the_same_cve() {
        let mut c = candidate("CVE-3");
        c.description = Some("nginx flaw".into());
        c.cpes = vec![cpe("f5", "nginx", Some("1.25.0"))];
        let m = evaluate(&nginx_watch(), &c).unwrap().unwrap();
        assert_eq!(m.confidence, Confidence::High);
        assert_eq!(m.kind, MatchKind::Cpe);
    }

    #[test]
    fn an_exclusion_vetoes_even_an_exact_cpe_hit() {
        let mut c = candidate("CVE-4");
        c.description = Some("A flaw in Nginx Proxy Manager admin UI".into());
        c.cpes = vec![cpe("f5", "nginx", Some("1.25.0"))];
        assert!(
            evaluate(&nginx_watch(), &c).unwrap().is_none(),
            "keywords.none exists to kill a known noise source outright"
        );
    }

    #[test]
    fn a_different_vendors_product_does_not_match_on_cpe() {
        let mut c = candidate("CVE-5");
        // igor_sysoev also ships a product called nginx; this watch asked for f5 only.
        c.cpes = vec![cpe("igor_sysoev", "nginx", Some("0.3.11"))];
        let m = evaluate(&nginx_watch(), &c).unwrap().unwrap();
        assert_eq!(
            m.kind,
            MatchKind::Keyword,
            "it still matches by keyword, but only as review"
        );
        assert_eq!(m.confidence, Confidence::Review);
    }

    #[test]
    fn the_severity_floor_filters_scored_cves() {
        let w = watch(
            r#"
            [[watch]]
            name = "wp"
            severity_min = "high"
              [[watch.cpe]]
              vendor = "wordpress"
              product = "wordpress"
            "#,
        );
        let mut c = candidate("CVE-6");
        c.severity = Some(Severity::Medium);
        c.cpes = vec![cpe("wordpress", "wordpress", Some("6.0"))];
        assert!(evaluate(&w, &c).unwrap().is_none());

        c.severity = Some(Severity::Critical);
        assert!(evaluate(&w, &c).unwrap().is_some());
    }

    #[test]
    fn a_kev_entry_bypasses_the_severity_floor() {
        // A low-scored CVE that is being actively exploited still has to get through.
        let w = watch(
            r#"
            [[watch]]
            name = "wp"
            severity_min = "critical"
              [[watch.cpe]]
              vendor = "wordpress"
              product = "wordpress"
            "#,
        );
        let mut c = candidate("CVE-7");
        c.severity = Some(Severity::Medium);
        c.cpes = vec![cpe("wordpress", "wordpress", Some("6.0"))];
        c.kev = Some(CandidateKev {
            vendor_project: Some("WordPress".into()),
            product: Some("WordPress".into()),
            ..Default::default()
        });
        let m = evaluate(&w, &c).unwrap().unwrap();
        assert_eq!(m.confidence, Confidence::High);
    }

    #[test]
    fn an_unscored_cve_survives_the_floor_as_review() {
        // Awaiting Analysis: no CPE data and no CVSS score. Dropping these would hide
        // every brand-new vulnerability for days.
        let mut c = candidate("CVE-8");
        c.severity = None;
        c.description = Some("nginx request smuggling".into());
        let m = evaluate(&nginx_watch(), &c).unwrap().unwrap();
        assert_eq!(m.confidence, Confidence::Review);
        assert!(m.evidence.contains("unscored"), "{}", m.evidence);
    }

    #[test]
    fn kev_matches_on_catalog_text_without_any_cpe_data() {
        let mut c = candidate("CVE-9");
        c.kev = Some(CandidateKev {
            vendor_project: Some("F5".into()),
            product: Some("NGINX".into()),
            ..Default::default()
        });
        let m = evaluate(&nginx_watch(), &c).unwrap().unwrap();
        assert_eq!(m.kind, MatchKind::Kev);
        assert_eq!(m.confidence, Confidence::High);
    }

    #[test]
    fn a_kev_entry_for_another_product_from_the_same_vendor_does_not_match() {
        // Taken from the live catalog: "F5 / BIG-IP" must not satisfy an f5:nginx watch.
        // Matching a KEV entry on its vendor alone makes a watch fire on everything that
        // vendor ships.
        let mut c = candidate("CVE-2025-53521");
        c.kev = Some(CandidateKev {
            vendor_project: Some("F5".into()),
            product: Some("BIG-IP".into()),
            ..Default::default()
        });
        assert!(evaluate(&nginx_watch(), &c).unwrap().is_none());

        // The same vendor's actual nginx entry must still match.
        c.kev = Some(CandidateKev {
            vendor_project: Some("F5".into()),
            product: Some("NGINX".into()),
            ..Default::default()
        });
        assert_eq!(
            evaluate(&nginx_watch(), &c).unwrap().unwrap().kind,
            MatchKind::Kev
        );
    }

    #[test]
    fn a_kev_product_named_only_in_the_vendor_field_still_matches() {
        // The live catalog spells WordPress core as vendorProject "WordPress",
        // product "Core", so the product selector has to be tried against both fields.
        let w = watch(
            r#"
            [[watch]]
            name = "wordpress"
              [[watch.cpe]]
              vendor = "wordpress"
              product = "wordpress"
            "#,
        );
        let mut c = candidate("CVE-2026-63030");
        c.kev = Some(CandidateKev {
            vendor_project: Some("WordPress".into()),
            product: Some("Core".into()),
            ..Default::default()
        });
        assert_eq!(evaluate(&w, &c).unwrap().unwrap().kind, MatchKind::Kev);
    }

    #[test]
    fn a_version_range_excludes_out_of_range_cpes() {
        let w = watch(
            r#"
            [[watch]]
            name = "nginx"
              [[watch.cpe]]
              vendor = "f5"
              product = "nginx"
              version_range = ">=1.24.0, <1.27.0"
            "#,
        );
        let mut c = candidate("CVE-10");
        c.cpes = vec![cpe("f5", "nginx", Some("1.20.0"))];
        assert!(evaluate(&w, &c).unwrap().is_none(), "1.20.0 is below the range");

        c.cpes = vec![cpe("f5", "nginx", Some("1.25.1"))];
        assert_eq!(
            evaluate(&w, &c).unwrap().unwrap().confidence,
            Confidence::High
        );
    }

    #[test]
    fn an_unbounded_cpe_against_a_version_range_downgrades_to_review() {
        let w = watch(
            r#"
            [[watch]]
            name = "nginx"
              [[watch.cpe]]
              vendor = "f5"
              product = "nginx"
              version_range = ">=1.24.0"
            "#,
        );
        let mut c = candidate("CVE-11");
        // "every version of nginx is vulnerable" — nothing to intersect against.
        c.cpes = vec![cpe("f5", "nginx", None)];
        let m = evaluate(&w, &c).unwrap().unwrap();
        assert_eq!(m.confidence, Confidence::Review);
        assert!(m.evidence.contains("unbounded"), "{}", m.evidence);
    }

    #[test]
    fn a_disabled_watch_never_matches() {
        let mut w = nginx_watch();
        w.enabled = false;
        let mut c = candidate("CVE-12");
        c.cpes = vec![cpe("f5", "nginx", Some("1.25.0"))];
        assert!(evaluate(&w, &c).unwrap().is_none());
    }

    #[test]
    fn an_unrelated_cve_does_not_match() {
        let mut c = candidate("CVE-13");
        c.description = Some("A flaw in Apache httpd mod_proxy".into());
        c.cpes = vec![cpe("apache", "http_server", Some("2.4.0"))];
        assert!(evaluate(&nginx_watch(), &c).unwrap().is_none());
    }
}

