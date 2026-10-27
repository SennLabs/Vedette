//! Watch definitions, loaded from `watches.toml`.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
#[clap(rename_all = "lowercase")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    /// Parses NVD's `baseSeverity`, which is uppercase.
    pub fn parse_nvd(s: &str) -> Option<Self> {
        match s.to_ascii_uppercase().as_str() {
            "NONE" => Some(Self::None),
            "LOW" => Some(Self::Low),
            "MEDIUM" => Some(Self::Medium),
            "HIGH" => Some(Self::High),
            "CRITICAL" => Some(Self::Critical),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "NONE",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }
}

/// Which stored fields a keyword is allowed to match against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Description,
    Cpe,
    KevProduct,
    Refs,
}

fn default_fields() -> Vec<Field> {
    vec![Field::Description, Field::Cpe, Field::KevProduct]
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Keywords {
    /// Any one of these matching is enough.
    #[serde(default)]
    pub any: Vec<String>,
    /// Every one of these must match.
    #[serde(default)]
    pub all: Vec<String>,
    /// Any one of these matching vetoes the whole watch for that CVE.
    #[serde(default)]
    pub none: Vec<String>,
    #[serde(default = "default_fields")]
    pub fields: Vec<Field>,
    /// Treat the terms as regular expressions rather than case-insensitive substrings.
    #[serde(default)]
    pub regex: bool,
}

impl Keywords {
    /// True when the set can never produce a hit. `none` alone is an exclusion list with
    /// nothing to exclude from.
    fn cannot_match(&self) -> bool {
        self.any.is_empty() && self.all.is_empty()
    }
}

/// One vendor/product pair to match against NVD CPE data.
///
/// Written in `watches.toml` in any of three shapes, all equivalent:
///
/// ```toml
/// cpe = [
///   "f5:nginx",                                         # any version
///   { cpe = "nginx:nginx", versions = ">=1.24, <1.27" }, # version-bounded
///   { vendor = "f5", product = "nginx_plus" },          # the original long form
/// ]
/// ```
///
/// `Serialize` keeps the long form so `def_hash` is unchanged by how a selector is spelled.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct CpeSelector {
    pub vendor: String,
    pub product: String,
    /// e.g. `">=1.24.0, <1.27.0"`. Absent means every version matches.
    pub version_range: Option<String>,
}

impl CpeSelector {
    /// Parses the `vendor:product` shorthand.
    fn parse_short(s: &str) -> Result<Self, String> {
        match s.split(':').collect::<Vec<_>>()[..] {
            [vendor, product] if !vendor.trim().is_empty() && !product.trim().is_empty() => {
                Ok(Self {
                    vendor: vendor.trim().to_string(),
                    product: product.trim().to_string(),
                    version_range: None,
                })
            }
            _ => Err(format!(
                "invalid cpe `{s}`: expected \"vendor:product\", e.g. \"f5:nginx\""
            )),
        }
    }
}

/// The table forms of a selector, before they are checked for a consistent shape.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CpeTable {
    cpe: Option<String>,
    versions: Option<String>,
    vendor: Option<String>,
    product: Option<String>,
    version_range: Option<String>,
}

impl TryFrom<CpeTable> for CpeSelector {
    type Error = String;

    fn try_from(t: CpeTable) -> Result<Self, String> {
        let version_range = match (t.versions, t.version_range) {
            (Some(_), Some(_)) => {
                return Err("set `versions` or `version_range`, not both".into());
            }
            (a, b) => a.or(b),
        };
        let mut sel = match (t.cpe, t.vendor, t.product) {
            (Some(cpe), None, None) => Self::parse_short(&cpe)?,
            (None, Some(vendor), Some(product)) => Self {
                vendor,
                product,
                version_range: None,
            },
            (Some(_), _, _) => {
                return Err(
                    "set `cpe = \"vendor:product\"` or `vendor` + `product`, not both".into(),
                );
            }
            _ => {
                return Err(
                    "a cpe table needs `cpe = \"vendor:product\"` or both `vendor` and `product`"
                        .into(),
                );
            }
        };
        sel.version_range = version_range;
        Ok(sel)
    }
}

// Hand-written rather than `#[serde(untagged)]`: an untagged enum reports every mistake
// as "data did not match any variant", which hides a typo'd field name.
impl<'de> Deserialize<'de> for CpeSelector {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = CpeSelector;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("\"vendor:product\" or a table with `cpe` or `vendor`/`product`")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<CpeSelector, E> {
                CpeSelector::parse_short(s).map_err(E::custom)
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                m: A,
            ) -> Result<CpeSelector, A::Error> {
                let t = CpeTable::deserialize(serde::de::value::MapAccessDeserializer::new(m))?;
                CpeSelector::try_from(t).map_err(serde::de::Error::custom)
            }
        }
        d.deserialize_any(V)
    }
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Watch {
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Channel names from `vedette.toml`. Empty means "every channel".
    #[serde(default)]
    pub channels: Vec<String>,
    /// Floor on CVSS severity. KEV matches deliberately bypass this.
    #[serde(default)]
    pub severity_min: Option<Severity>,
    #[serde(default)]
    pub cpe: Vec<CpeSelector>,
    #[serde(default)]
    pub keywords: Keywords,
}

impl Watch {
    /// Stable hash of the matching-relevant definition. Changing it triggers a
    /// re-evaluation of the stored corpus; changing only `channels` does not.
    pub fn def_hash(&self) -> String {
        #[derive(Serialize)]
        struct Salient<'a> {
            cpe: &'a [CpeSelector],
            keywords: &'a Keywords,
            severity_min: Option<Severity>,
        }
        let json = serde_json::to_vec(&Salient {
            cpe: &self.cpe,
            keywords: &self.keywords,
            severity_min: self.severity_min,
        })
        .expect("watch definition is always serializable");
        hex::encode(Sha256::digest(&json))
    }

    pub fn definition_json(&self) -> String {
        serde_json::to_string(self).expect("watch definition is always serializable")
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchFile {
    #[serde(default, rename = "watch")]
    pub watches: Vec<Watch>,
}

impl WatchFile {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading watch file {}", path.display()))?;
        let parsed: Self = toml::from_str(&text)
            .with_context(|| format!("parsing watch file {}", path.display()))?;
        parsed.validate()?;
        Ok(parsed)
    }

    pub fn validate(&self) -> Result<()> {
        let mut seen = std::collections::HashSet::new();
        for w in &self.watches {
            if w.name.trim().is_empty() {
                return Err(anyhow!("a watch has an empty name"));
            }
            if !seen.insert(w.name.as_str()) {
                return Err(anyhow!("duplicate watch name `{}`", w.name));
            }
            if w.cpe.is_empty() && w.keywords.cannot_match() {
                return Err(anyhow!(
                    "watch `{}` declares neither a `cpe` selector nor any `any`/`all` \
                     keywords, so it can never match",
                    w.name
                ));
            }
            // Compile regexes now so a typo fails `watch validate` instead of the daemon.
            if w.keywords.regex {
                for term in w
                    .keywords
                    .any
                    .iter()
                    .chain(&w.keywords.all)
                    .chain(&w.keywords.none)
                {
                    regex::Regex::new(term).with_context(|| {
                        format!("watch `{}` has an invalid regex `{term}`", w.name)
                    })?;
                }
            }
            for c in &w.cpe {
                if c.vendor.trim().is_empty() || c.product.trim().is_empty() {
                    return Err(anyhow!(
                        "watch `{}` has a `cpe` selector with an empty vendor or product",
                        w.name
                    ));
                }
                if let Some(r) = &c.version_range {
                    crate::matcher::version::VersionRange::parse(r).with_context(|| {
                        format!("watch `{}` has an invalid version_range `{r}`", w.name)
                    })?;
                }
            }
        }
        Ok(())
    }
}

/// Shared `#[serde(default)]` helper for the channel config, which also defaults to true.
pub(crate) fn default_true_pub() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_correctly() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::Medium > Severity::Low);
        assert_eq!(Severity::parse_nvd("critical"), Some(Severity::Critical));
        assert_eq!(Severity::parse_nvd("bogus"), None);
    }

    #[test]
    fn parses_the_documented_watch_shape() {
        let f: WatchFile = toml::from_str(
            r#"
            [[watch]]
            name = "nginx"
            channels = ["secops-email"]
            severity_min = "medium"
              [[watch.cpe]]
              vendor = "f5"
              product = "nginx"
              version_range = ">=1.24.0, <1.27.0"
              [[watch.cpe]]
              vendor = "nginx"
              product = "nginx"
              [watch.keywords]
              any = ["nginx", "njs"]
              none = ["nginx proxy manager"]
              fields = ["description", "cpe", "kev_product", "refs"]
            "#,
        )
        .unwrap();
        f.validate().unwrap();
        let w = &f.watches[0];
        assert_eq!(w.cpe.len(), 2);
        assert!(w.enabled);
        assert_eq!(w.severity_min, Some(Severity::Medium));
    }

    #[test]
    fn every_cpe_spelling_parses_to_the_same_watch() {
        let short = r#"
            [[watch]]
            name = "nginx"
            cpe = [
              "f5:nginx",
              { cpe = "nginx:nginx", versions = ">=1.24.0, <1.27.0" },
            ]
            [watch.keywords]
            any = ["nginx"]
        "#;
        let long = r#"
            [[watch]]
            name = "nginx"
              [[watch.cpe]]
              vendor = "f5"
              product = "nginx"
              [[watch.cpe]]
              vendor = "nginx"
              product = "nginx"
              version_range = ">=1.24.0, <1.27.0"
              [watch.keywords]
              any = ["nginx"]
        "#;
        let mixed = r#"
            [[watch]]
            name = "nginx"
            cpe = [
              { vendor = "f5", product = "nginx" },
              { cpe = "nginx:nginx", version_range = ">=1.24.0, <1.27.0" },
            ]
            keywords.any = ["nginx"]
        "#;
        let parse = |s: &str| toml::from_str::<WatchFile>(s).unwrap().watches.remove(0);
        let (a, b, c) = (parse(short), parse(long), parse(mixed));
        assert_eq!(a.cpe, b.cpe);
        assert_eq!(a.cpe, c.cpe);
        assert_eq!(a.cpe[1].vendor, "nginx");
        assert_eq!(a.cpe[1].version_range.as_deref(), Some(">=1.24.0, <1.27.0"));
        // The spelling must not change the hash, or reformatting the file would trigger
        // a full re-evaluation of the stored corpus.
        assert_eq!(a.def_hash(), b.def_hash());
        assert_eq!(a.def_hash(), c.def_hash());
    }

    #[test]
    fn malformed_cpe_selectors_are_rejected_with_a_useful_message() {
        let err = |cpe: &str| {
            let src = format!("[[watch]]\nname = \"a\"\ncpe = [{cpe}]\n");
            toml::from_str::<WatchFile>(&src).unwrap_err().to_string()
        };
        assert!(
            err(r#""nginx""#).contains("vendor:product"),
            "{}",
            err(r#""nginx""#)
        );
        assert!(err(r#""a:b:c""#).contains("vendor:product"));
        assert!(err(r#"":nginx""#).contains("vendor:product"));
        assert!(err(r#"{ cpe = "f5:nginx", vendor = "f5" }"#).contains("not both"));
        assert!(
            err(r#"{ cpe = "f5:nginx", versions = ">=1", version_range = ">=1" }"#)
                .contains("not both")
        );
        assert!(err(r#"{ vendor = "f5" }"#).contains("needs"));
        // A typo'd field name must be named, not swallowed by a generic error.
        assert!(err(r#"{ cpe = "f5:nginx", version = ">=1" }"#).contains("version"));
    }

    #[test]
    fn a_watch_that_cannot_match_is_rejected() {
        let f: WatchFile = toml::from_str("[[watch]]\nname = \"empty\"\n").unwrap();
        let err = f.validate().unwrap_err().to_string();
        assert!(err.contains("never match"), "{err}");

        // An exclusion list with nothing to exclude from is the same mistake.
        let f: WatchFile =
            toml::from_str("[[watch]]\nname = \"x\"\n[watch.keywords]\nnone = [\"a\"]\n")
                .unwrap();
        assert!(f.validate().is_err());
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let f: WatchFile = toml::from_str(
            r#"
            [[watch]]
            name = "a"
            [watch.keywords]
            any = ["x"]
            [[watch]]
            name = "a"
            [watch.keywords]
            any = ["y"]
            "#,
        )
        .unwrap();
        assert!(f.validate().unwrap_err().to_string().contains("duplicate"));
    }

    #[test]
    fn def_hash_ignores_channels_but_tracks_matching_fields() {
        let base = r#"
            [[watch]]
            name = "a"
            channels = ["x"]
            [watch.keywords]
            any = ["nginx"]
        "#;
        let changed_channel = r#"
            [[watch]]
            name = "a"
            channels = ["y", "z"]
            [watch.keywords]
            any = ["nginx"]
        "#;
        let changed_term = r#"
            [[watch]]
            name = "a"
            channels = ["x"]
            [watch.keywords]
            any = ["apache"]
        "#;
        let h = |s: &str| toml::from_str::<WatchFile>(s).unwrap().watches[0].def_hash();
        assert_eq!(h(base), h(changed_channel));
        assert_ne!(h(base), h(changed_term));
    }
}
