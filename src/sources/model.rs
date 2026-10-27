//! Wire models for both upstream feeds, plus the normalized rows we store.

use serde::{Deserialize, Serialize};

// ------------------------------------------------------------------ CISA KEV

#[derive(Debug, Clone, Deserialize)]
pub struct KevCatalog {
    #[serde(default)]
    pub title: String,
    #[serde(rename = "catalogVersion", default)]
    pub catalog_version: String,
    #[serde(rename = "dateReleased", default)]
    pub date_released: String,
    #[serde(default)]
    pub count: usize,
    pub vulnerabilities: Vec<KevEntry>,
}

/// One KEV catalog entry. Every field is currently populated on all entries, but they stay
/// optional: `forensicTriage` is a recent BOD 26-04 addition and older mirrors omit it.
#[derive(Debug, Clone, Deserialize)]
pub struct KevEntry {
    // Note the capitalisation: `cveID`, which camelCase renaming would not produce.
    #[serde(rename = "cveID")]
    pub cve_id: String,
    #[serde(rename = "vendorProject", default)]
    pub vendor_project: Option<String>,
    #[serde(default)]
    pub product: Option<String>,
    #[serde(rename = "vulnerabilityName", default)]
    pub vulnerability_name: Option<String>,
    #[serde(rename = "dateAdded", default)]
    pub date_added: Option<String>,
    #[serde(rename = "dueDate", default)]
    pub due_date: Option<String>,
    #[serde(rename = "shortDescription", default)]
    pub short_description: Option<String>,
    #[serde(rename = "requiredAction", default)]
    pub required_action: Option<String>,
    #[serde(rename = "knownRansomwareCampaignUse", default)]
    pub known_ransomware_campaign_use: Option<String>,
    #[serde(rename = "forensicTriage", default)]
    pub forensic_triage: Option<String>,
    #[serde(default)]
    pub notes: Option<String>,
    /// A JSON array of CWE identifiers, e.g. `["CWE-89"]`.
    #[serde(default)]
    pub cwes: Vec<String>,
}

impl KevEntry {
    pub fn known_ransomware(&self) -> bool {
        self.known_ransomware_campaign_use
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("known"))
    }

    pub fn forensic_triage_required(&self) -> bool {
        self.forensic_triage
            .as_deref()
            .is_some_and(|v| v.eq_ignore_ascii_case("yes"))
    }
}

// ----------------------------------------------------------------- NVD CVE 2.0

#[derive(Debug, Clone, Deserialize)]
pub struct NvdCveResponse {
    #[serde(rename = "resultsPerPage")]
    pub results_per_page: u32,
    #[serde(rename = "startIndex")]
    pub start_index: u32,
    #[serde(rename = "totalResults")]
    pub total_results: u32,
    #[serde(default)]
    pub vulnerabilities: Vec<NvdVulnerability>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NvdVulnerability {
    pub cve: NvdCve,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCve {
    pub id: String,
    pub published: String,
    #[serde(rename = "lastModified")]
    pub last_modified: String,
    #[serde(rename = "vulnStatus", default)]
    pub vuln_status: Option<String>,
    #[serde(default)]
    pub descriptions: Vec<NvdLangText>,
    #[serde(default)]
    pub metrics: NvdMetrics,
    #[serde(default)]
    pub weaknesses: Vec<NvdWeakness>,
    #[serde(default)]
    pub configurations: Vec<NvdConfiguration>,
    #[serde(default)]
    pub references: Vec<NvdReference>,
    #[serde(rename = "cisaExploitAdd", default)]
    pub cisa_exploit_add: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdLangText {
    pub lang: String,
    pub value: String,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct NvdMetrics {
    #[serde(rename = "cvssMetricV40", default)]
    pub v40: Vec<NvdMetric>,
    #[serde(rename = "cvssMetricV31", default)]
    pub v31: Vec<NvdMetric>,
    #[serde(rename = "cvssMetricV30", default)]
    pub v30: Vec<NvdMetric>,
    #[serde(rename = "cvssMetricV2", default)]
    pub v2: Vec<NvdMetricV2>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdMetric {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(rename = "cvssData")]
    pub cvss_data: NvdCvssData,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCvssData {
    #[serde(default)]
    pub version: Option<String>,
    #[serde(rename = "vectorString", default)]
    pub vector_string: Option<String>,
    #[serde(rename = "baseScore", default)]
    pub base_score: Option<f64>,
    #[serde(rename = "baseSeverity", default)]
    pub base_severity: Option<String>,
}

/// CVSS v2 puts `baseSeverity` on the metric rather than inside `cvssData`.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdMetricV2 {
    #[serde(rename = "cvssData")]
    pub cvss_data: NvdCvssData,
    #[serde(rename = "baseSeverity", default)]
    pub base_severity: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdWeakness {
    #[serde(default)]
    pub description: Vec<NvdLangText>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdReference {
    pub url: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdConfiguration {
    #[serde(default)]
    pub nodes: Vec<NvdNode>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdNode {
    #[serde(rename = "cpeMatch", default)]
    pub cpe_match: Vec<NvdCpeMatch>,
    #[serde(default)]
    pub negate: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NvdCpeMatch {
    #[serde(default)]
    pub vulnerable: bool,
    pub criteria: String,
    #[serde(rename = "versionStartIncluding", default)]
    pub version_start_including: Option<String>,
    #[serde(rename = "versionStartExcluding", default)]
    pub version_start_excluding: Option<String>,
    #[serde(rename = "versionEndIncluding", default)]
    pub version_end_including: Option<String>,
    #[serde(rename = "versionEndExcluding", default)]
    pub version_end_excluding: Option<String>,
}

// -------------------------------------------------------------- stored shapes

/// `(version, base_score, base_severity, vector_string)` as selected by
/// [`NvdCve::best_cvss`].
pub type CvssSummary = (String, Option<f64>, Option<String>, Option<String>);

/// A CPE row flattened out of `configurations`, ready to insert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpeRow {
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: Option<String>,
    pub criteria: String,
    pub ver_start: Option<String>,
    pub ver_start_incl: bool,
    pub ver_end: Option<String>,
    pub ver_end_incl: bool,
}

/// The fields the escalation differ compares between two sightings of one CVE.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CveSnapshot {
    pub id: String,
    pub last_modified: String,
    pub vuln_status: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_severity: Option<String>,
    pub in_kev: bool,
    pub has_exploit_ref: bool,
}

#[derive(Debug, Clone)]
pub struct CveDelta {
    pub id: String,
    pub is_new: bool,
    pub old: Option<CveSnapshot>,
    pub new: CveSnapshot,
}

impl NvdCve {
    pub fn english_description(&self) -> Option<&str> {
        self.descriptions
            .iter()
            .find(|d| d.lang == "en")
            .or_else(|| self.descriptions.first())
            .map(|d| d.value.as_str())
    }

    /// Picks the most recent CVSS version present, preferring NVD's own analysis over a
    /// CNA's self-assessment when both exist for that version.
    ///
    /// Returns `(version, base_score, base_severity, vector_string)`.
    pub fn best_cvss(&self) -> Option<CvssSummary> {
        fn primary(metrics: &[NvdMetric]) -> Option<&NvdMetric> {
            metrics
                .iter()
                .find(|m| m.kind.as_deref() == Some("Primary"))
                .or_else(|| metrics.first())
        }
        for (ver, set) in [
            ("4.0", &self.metrics.v40),
            ("3.1", &self.metrics.v31),
            ("3.0", &self.metrics.v30),
        ] {
            if let Some(m) = primary(set) {
                return Some((
                    m.cvss_data.version.clone().unwrap_or_else(|| ver.to_string()),
                    m.cvss_data.base_score,
                    m.cvss_data.base_severity.clone(),
                    m.cvss_data.vector_string.clone(),
                ));
            }
        }
        let m = self.metrics.v2.first()?;
        Some((
            m.cvss_data.version.clone().unwrap_or_else(|| "2.0".to_string()),
            m.cvss_data.base_score,
            // v2 carries baseSeverity a level up from cvssData.
            m.base_severity.clone().or_else(|| m.cvss_data.base_severity.clone()),
            m.cvss_data.vector_string.clone(),
        ))
    }

    pub fn cwe_ids(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .weaknesses
            .iter()
            .flat_map(|w| w.description.iter())
            .map(|d| d.value.clone())
            .filter(|v| v.starts_with("CWE-"))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    pub fn has_exploit_ref(&self) -> bool {
        self.references
            .iter()
            .any(|r| r.tags.iter().any(|t| t.eq_ignore_ascii_case("Exploit")))
    }

    /// Flattens `configurations[].nodes[].cpeMatch[]` into insertable rows, keeping only
    /// vulnerable entries from non-negated nodes. A node's non-vulnerable members describe
    /// the platform a vulnerable component runs on, not something we watch for.
    pub fn cpe_rows(&self) -> Vec<CpeRow> {
        let mut out = Vec::new();
        for cfg in &self.configurations {
            for node in &cfg.nodes {
                if node.negate.unwrap_or(false) {
                    continue;
                }
                for m in &node.cpe_match {
                    if !m.vulnerable {
                        continue;
                    }
                    if let Some(row) = parse_cpe(&m.criteria) {
                        let (start, start_incl) = match (
                            &m.version_start_including,
                            &m.version_start_excluding,
                        ) {
                            (Some(v), _) => (Some(v.clone()), true),
                            (None, Some(v)) => (Some(v.clone()), false),
                            _ => (None, false),
                        };
                        let (end, end_incl) =
                            match (&m.version_end_including, &m.version_end_excluding) {
                                (Some(v), _) => (Some(v.clone()), true),
                                (None, Some(v)) => (Some(v.clone()), false),
                                _ => (None, false),
                            };
                        out.push(CpeRow {
                            ver_start: start,
                            ver_start_incl: start_incl,
                            ver_end: end,
                            ver_end_incl: end_incl,
                            ..row
                        });
                    }
                }
            }
        }
        out.sort_by(|a, b| {
            (&a.vendor, &a.product, &a.criteria).cmp(&(&b.vendor, &b.product, &b.criteria))
        });
        out.dedup();
        out
    }
}

/// Splits a `cpe:2.3:` URI into the fields we index on.
///
/// CPE escapes literal colons as `\:`, so a naive `split(':')` corrupts those components.
pub fn parse_cpe(criteria: &str) -> Option<CpeRow> {
    let rest = criteria.strip_prefix("cpe:2.3:")?;
    let mut fields: Vec<String> = Vec::with_capacity(11);
    let mut cur = String::new();
    let mut escaped = false;
    for ch in rest.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
            cur.push(ch);
        } else if ch == ':' {
            fields.push(std::mem::take(&mut cur));
        } else {
            cur.push(ch);
        }
    }
    fields.push(cur);
    // cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:... — after stripping the
    // prefix, version is field 3. Reading field 4 would pick up `update` instead.
    if fields.len() < 4 {
        return None;
    }
    let version = fields[3].clone();
    Some(CpeRow {
        part: fields[0].clone(),
        vendor: fields[1].to_ascii_lowercase(),
        product: fields[2].to_ascii_lowercase(),
        version: if crate::matcher::version::is_wildcard(&version) {
            None
        } else {
            Some(version)
        },
        criteria: criteria.to_string(),
        ver_start: None,
        ver_start_incl: false,
        ver_end: None,
        ver_end_incl: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_cpe() {
        let r = parse_cpe("cpe:2.3:a:f5:nginx:1.25.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!(r.part, "a");
        assert_eq!(r.vendor, "f5");
        assert_eq!(r.product, "nginx");
        assert_eq!(r.version.as_deref(), Some("1.25.0"));
    }

    #[test]
    fn wildcard_version_becomes_none() {
        let r = parse_cpe("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*").unwrap();
        assert_eq!(r.version, None);
        let r = parse_cpe("cpe:2.3:h:siemens:device:-:*:*:*:*:*:*:*").unwrap();
        assert_eq!(r.version, None);
    }

    #[test]
    fn respects_escaped_colons_in_the_product_field() {
        // This real Siemens CPE contains an escaped slash; escaped colons occur too and a
        // naive split(':') would shift every later field.
        let r = parse_cpe(
            r"cpe:2.3:o:siemens:simatic_s7-1500_cpu_1518f-4_pn\/dp_mfp_firmware:*:*:*:*:*:*:*:*",
        )
        .unwrap();
        assert_eq!(r.vendor, "siemens");
        assert!(r.product.contains("pn\\/dp_mfp_firmware"), "{}", r.product);
        assert_eq!(r.version, None);
    }

    #[test]
    fn reads_version_not_update_from_the_criteria() {
        // The `update` component sits immediately after `version`; an off-by-one here
        // silently reports the wrong field for every single CPE row.
        let r = parse_cpe("cpe:2.3:a:vendor:product:1.2.3:sp1:*:*:*:*:*:*").unwrap();
        assert_eq!(r.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn rejects_non_cpe23_strings() {
        assert!(parse_cpe("cpe:/a:f5:nginx").is_none());
        assert!(parse_cpe("nonsense").is_none());
        assert!(parse_cpe("cpe:2.3:a:f5").is_none(), "too few fields");
        assert!(parse_cpe("cpe:2.3:a:f5:nginx").is_none(), "no version field");
    }

    #[test]
    fn vendor_and_product_are_case_folded() {
        let r = parse_cpe("cpe:2.3:a:F5:NGINX:1.0:*:*:*:*:*:*:*").unwrap();
        assert_eq!((r.vendor.as_str(), r.product.as_str()), ("f5", "nginx"));
    }
}
