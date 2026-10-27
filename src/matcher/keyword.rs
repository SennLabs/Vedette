//! Keyword and regex matching over a CVE's text fields.

use super::{Candidate, CandidateKev};
use crate::config::{Field, Keywords};
use anyhow::{Context, Result};
use regex::RegexBuilder;

/// A compiled keyword set. Compiling once per watch rather than once per CVE matters:
/// a poll cycle evaluates thousands of CVEs against the same handful of watches.
pub struct KeywordMatcher<'a> {
    spec: &'a Keywords,
    any: Vec<Term>,
    all: Vec<Term>,
    none: Vec<Term>,
}

enum Term {
    /// Case-insensitive substring, the default.
    Substring { needle: String, original: String },
    Regex { re: regex::Regex, original: String },
}

impl Term {
    fn build(raw: &str, as_regex: bool) -> Result<Self> {
        if as_regex {
            Ok(Term::Regex {
                re: RegexBuilder::new(raw)
                    .case_insensitive(true)
                    .build()
                    .with_context(|| format!("invalid regex `{raw}`"))?,
                original: raw.to_string(),
            })
        } else {
            Ok(Term::Substring {
                needle: raw.to_ascii_lowercase(),
                original: raw.to_string(),
            })
        }
    }

    /// `haystack` must already be lowercased for the substring path.
    fn matches(&self, haystack: &str) -> bool {
        match self {
            Term::Substring { needle, .. } => haystack.contains(needle.as_str()),
            Term::Regex { re, .. } => re.is_match(haystack),
        }
    }

    fn original(&self) -> &str {
        match self {
            Term::Substring { original, .. } | Term::Regex { original, .. } => original,
        }
    }
}

impl<'a> KeywordMatcher<'a> {
    pub fn compile(spec: &'a Keywords) -> Result<Self> {
        let build = |terms: &[String]| -> Result<Vec<Term>> {
            terms.iter().map(|t| Term::build(t, spec.regex)).collect()
        };
        Ok(Self {
            spec,
            any: build(&spec.any)?,
            all: build(&spec.all)?,
            none: build(&spec.none)?,
        })
    }

    /// The text this watch is allowed to look at, lowercased, tagged with its field name.
    fn haystacks(&self, c: &Candidate) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        for field in &self.spec.fields {
            match field {
                Field::Description => {
                    if let Some(d) = &c.description {
                        out.push(("description", d.to_ascii_lowercase()));
                    }
                }
                Field::Cpe => {
                    for cpe in &c.cpes {
                        // The criteria string carries vendor and product together, which
                        // is what a loose product-name term is really looking for.
                        out.push(("cpe", cpe.criteria.to_ascii_lowercase()));
                    }
                }
                Field::KevProduct => {
                    if let Some(k) = &c.kev {
                        for s in [&k.vendor_project, &k.product, &k.vulnerability_name]
                            .into_iter()
                            .flatten()
                        {
                            out.push(("kev_product", s.to_ascii_lowercase()));
                        }
                    }
                }
                Field::Refs => {
                    for url in &c.reference_urls {
                        out.push(("refs", url.to_ascii_lowercase()));
                    }
                }
            }
        }
        out
    }

    /// True when any `none` term appears anywhere this watch is allowed to look.
    ///
    /// Exclusions deliberately scan the *same* fields as inclusions: an exclusion that
    /// could not see the text that caused the false positive would be useless.
    pub fn is_excluded(&self, c: &Candidate) -> bool {
        if self.none.is_empty() {
            return false;
        }
        let haystacks = self.haystacks(c);
        self.none
            .iter()
            .any(|t| haystacks.iter().any(|(_, h)| t.matches(h)))
    }

    /// The first `any` term that hits, with the field it hit in, once every `all` term is
    /// satisfied somewhere.
    pub fn first_hit(&self, c: &Candidate) -> Option<(String, &'static str)> {
        if self.any.is_empty() && self.all.is_empty() {
            return None;
        }
        let haystacks = self.haystacks(c);
        if haystacks.is_empty() {
            return None;
        }
        // Every `all` term must appear somewhere, though not necessarily in one field.
        for t in &self.all {
            if !haystacks.iter().any(|(_, h)| t.matches(h)) {
                return None;
            }
        }
        for t in &self.any {
            if let Some((field, _)) = haystacks.iter().find(|(_, h)| t.matches(h)) {
                return Some((t.original().to_string(), field));
            }
        }
        // `all` alone, with no `any` terms, is a complete specification on its own.
        if self.any.is_empty() && !self.all.is_empty() {
            return self.all.first().map(|t| (t.original().to_string(), "all"));
        }
        None
    }

    /// Same as `first_hit`, restricted to the KEV catalog's own text. Used so a KEV
    /// entry can match on the strength of the catalog alone, before NVD analysis lands.
    pub fn first_hit_in_kev(&self, kev: &CandidateKev) -> Option<String> {
        let haystacks: Vec<String> = [
            &kev.vendor_project,
            &kev.product,
            &kev.vulnerability_name,
        ]
        .into_iter()
        .flatten()
        .map(|s| s.to_ascii_lowercase())
        .collect();
        if haystacks.is_empty() {
            return None;
        }
        for t in &self.none {
            if haystacks.iter().any(|h| t.matches(h)) {
                return None;
            }
        }
        self.any
            .iter()
            .find(|t| haystacks.iter().any(|h| t.matches(h)))
            .map(|t| t.original().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::matcher::CandidateCpe;

    fn kw(toml_src: &str) -> Keywords {
        toml::from_str(toml_src).unwrap()
    }

    fn cand(description: &str) -> Candidate {
        Candidate {
            id: "CVE-X".into(),
            description: Some(description.into()),
            ..Default::default()
        }
    }

    #[test]
    fn any_matches_case_insensitively() {
        let k = kw(r#"any = ["NGINX"]"#);
        let m = KeywordMatcher::compile(&k).unwrap();
        let (term, field) = m.first_hit(&cand("a flaw in nginx")).unwrap();
        assert_eq!(term, "NGINX", "the configured spelling is reported back");
        assert_eq!(field, "description");
    }

    #[test]
    fn all_requires_every_term() {
        let k = kw(r#"all = ["nginx", "smuggling"]"#);
        let m = KeywordMatcher::compile(&k).unwrap();
        assert!(m.first_hit(&cand("nginx request smuggling")).is_some());
        assert!(
            m.first_hit(&cand("nginx buffer overflow")).is_none(),
            "one of two terms is not enough"
        );
    }

    #[test]
    fn none_vetoes() {
        let k = kw(r#"any = ["nginx"]
none = ["nginx proxy manager"]"#);
        let m = KeywordMatcher::compile(&k).unwrap();
        assert!(!m.is_excluded(&cand("nginx flaw")));
        assert!(m.is_excluded(&cand("Nginx Proxy Manager auth bypass")));
    }

    #[test]
    fn fields_are_honoured() {
        // Default fields exclude `refs`, so a term that only appears in a URL must miss.
        let k = kw(r#"any = ["example"]"#);
        let m = KeywordMatcher::compile(&k).unwrap();
        let mut c = cand("unrelated text");
        c.reference_urls = vec!["https://example.test/advisory".into()];
        assert!(m.first_hit(&c).is_none(), "refs is not a default field");

        let k2 = kw(r#"any = ["example"]
fields = ["description", "refs"]"#);
        let m2 = KeywordMatcher::compile(&k2).unwrap();
        assert_eq!(m2.first_hit(&c).unwrap().1, "refs");
    }

    #[test]
    fn matches_against_cpe_criteria_strings() {
        let k = kw(r#"any = ["nginx"]
fields = ["cpe"]"#);
        let m = KeywordMatcher::compile(&k).unwrap();
        let mut c = cand("no product name here");
        c.cpes = vec![CandidateCpe {
            criteria: "cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*".into(),
            ..Default::default()
        }];
        assert_eq!(m.first_hit(&c).unwrap().1, "cpe");
    }

    #[test]
    fn regex_mode_compiles_and_matches() {
        let k = kw(r#"any = ["nginx\\s+1\\.2[45]"]
regex = true"#);
        let m = KeywordMatcher::compile(&k).unwrap();
        assert!(m.first_hit(&cand("affects nginx 1.25 only")).is_some());
        assert!(m.first_hit(&cand("affects nginx 1.18")).is_none());
    }

    #[test]
    fn an_invalid_regex_fails_at_compile_time() {
        let k = kw(r#"any = ["nginx(unclosed"]
regex = true"#);
        assert!(KeywordMatcher::compile(&k).is_err());
    }

    #[test]
    fn substring_mode_does_not_treat_terms_as_regex() {
        // A term with regex metacharacters must be taken literally by default.
        let k = kw(r#"any = ["nginx(1.25)"]"#);
        let m = KeywordMatcher::compile(&k).unwrap();
        assert!(m.first_hit(&cand("product nginx(1.25) is affected")).is_some());
        assert!(m.first_hit(&cand("product nginx1.25 is affected")).is_none());
    }

    #[test]
    fn an_empty_spec_never_matches() {
        let k = kw("");
        let m = KeywordMatcher::compile(&k).unwrap();
        assert!(m.first_hit(&cand("nginx")).is_none());
        assert!(!m.is_excluded(&cand("nginx")));
    }

    #[test]
    fn kev_text_is_searched_independently() {
        let k = kw(r#"any = ["nginx"]"#);
        let m = KeywordMatcher::compile(&k).unwrap();
        let kev = CandidateKev {
            vendor_project: Some("F5".into()),
            product: Some("NGINX Plus".into()),
            ..Default::default()
        };
        assert_eq!(m.first_hit_in_kev(&kev).as_deref(), Some("nginx"));
    }

    #[test]
    fn exclusions_apply_to_kev_text_too() {
        let k = kw(r#"any = ["nginx"]
none = ["proxy manager"]"#);
        let m = KeywordMatcher::compile(&k).unwrap();
        let kev = CandidateKev {
            product: Some("Nginx Proxy Manager".into()),
            ..Default::default()
        };
        assert!(m.first_hit_in_kev(&kev).is_none());
    }
}
