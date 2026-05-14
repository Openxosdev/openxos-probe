use aho_corasick::AhoCorasick;
use anyhow::{Context, Result};
use regex::Regex;
use reqwest::header::HeaderMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const JS_VERSION_PATTERNS: &[(&str, &str, &str)] = &[
    (r"react[@.](\d+\.\d+\.\d+)", "React", "version"),
    (
        r"__REACT_DEVTOOLS_GLOBAL_HOOK__",
        "React DevTools",
        "dev_mode",
    ),
    (r"vue@(\d+\.\d+\.\d+)", "Vue.js", "version"),
    (r#""version"\s*[:\s"]*(\d+\.\d+\.\d+)"#, "Vue.js", "version"),
    (r#"ng-version=['"](\d+\.\d+\.\d+)"#, "Angular", "version"),
    (r"angular@(\d+\.\d+\.\d+)", "Angular", "version"),
    (r"next@(\d+\.\d+\.\d+)", "Next.js", "version"),
    (r"gatsby@(\d+\.\d+\.\d+)", "Gatsby", "version"),
    (r"svelte@(\d+\.\d+\.\d+)", "Svelte", "version"),
];

#[derive(Debug, Clone)]
pub struct FrameworkVersion {
    pub name: String,
    pub version: Option<String>,
    pub is_dev_mode: bool,
}

pub fn detect_js_version(body: &str) -> Vec<FrameworkVersion> {
    let mut versions = Vec::new();

    for (pattern, name, info_type) in JS_VERSION_PATTERNS {
        let re = Regex::new(pattern).unwrap();

        if let Some(caps) = re.captures(body) {
            let is_dev_mode = *info_type == "dev_mode";
            let version = if *info_type == "version" {
                caps.get(1).map(|m| m.as_str().to_string())
            } else {
                None
            };

            if !versions
                .iter()
                .any(|v: &FrameworkVersion| v.name == *name && v.version == version)
            {
                versions.push(FrameworkVersion {
                    name: name.to_string(),
                    version,
                    is_dev_mode,
                });
            }
        }
    }

    if body.contains("sourceMappingURL") || body.contains("sourceMap") {
        if !versions
            .iter()
            .any(|v: &FrameworkVersion| v.name.contains("Source Maps"))
        {
            versions.push(FrameworkVersion {
                name: "Source Maps Exposed".to_string(),
                version: None,
                is_dev_mode: true,
            });
        }
    }

    versions
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TechnologyMatch {
    pub name: String,
    pub confidence: u8,
    pub evidence: Vec<String>,
    pub version: Option<String>,
    pub is_dev_mode: bool,
}

#[derive(Debug, Clone)]
pub struct LoadedSignatures {
    pub signatures: Vec<TechSignature>,
    pub(crate) body_matcher: Option<AhoCorasick>,
    #[allow(dead_code)]
    pub(crate) body_patterns: Vec<String>,
    pub(crate) sig_name_map: Vec<String>,
}

impl<'de> Deserialize<'de> for LoadedSignatures {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let signatures = Vec::<TechSignature>::deserialize(deserializer)?;
        LoadedSignatures::from_signatures(signatures)
            .map_err(|e| serde::de::Error::custom(e.to_string()))
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct TechSignature {
    pub name: String,
    #[serde(default)]
    pub headers: Vec<HeaderSignature>,
    #[serde(default)]
    pub body: Vec<String>,
    #[serde(default)]
    pub path_probes: Vec<PathProbeSignature>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HeaderSignature {
    pub name: String,
    pub contains: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PathProbeSignature {
    pub path: String,
    #[serde(default)]
    pub status_any_of: Vec<u16>,
    #[serde(default)]
    pub body_contains: Vec<String>,
}

impl LoadedSignatures {
    pub fn from_signatures(signatures: Vec<TechSignature>) -> Result<Self> {
        let mut body_patterns: Vec<String> = Vec::new();
        let mut sig_name_map: Vec<String> = Vec::new();

        for sig in &signatures {
            for pattern in &sig.body {
                body_patterns.push(pattern.to_ascii_lowercase());
                sig_name_map.push(sig.name.clone());
            }
        }

        let body_matcher = if body_patterns.is_empty() {
            None
        } else {
            Some(AhoCorasick::new(&body_patterns)?)
        };

        Ok(Self {
            signatures,
            body_matcher,
            body_patterns,
            sig_name_map,
        })
    }

    pub fn load_from_dir(path: &Path) -> Result<Self> {
        let mut signatures = Vec::new();
        if !path.exists() {
            return Ok(Self {
                signatures,
                body_matcher: None,
                body_patterns: Vec::new(),
                sig_name_map: Vec::new(),
            });
        }

        for entry in fs::read_dir(path).with_context(|| format!("failed to read {:?}", path))? {
            let entry = entry?;
            let entry_path = entry.path();
            if !entry_path.is_file()
                || entry_path.extension().and_then(|ext| ext.to_str()) != Some("json")
            {
                continue;
            }

            let content = fs::read_to_string(&entry_path)
                .with_context(|| format!("failed to read signature file {:?}", entry_path))?;
            let parsed: Vec<TechSignature> = serde_json::from_str(&content)
                .with_context(|| format!("invalid signature JSON in {:?}", entry_path))?;
            for sig in parsed {
                validate_signature(&sig)
                    .with_context(|| format!("invalid signature in {:?}", entry_path))?;
                signatures.push(sig);
            }
        }

        Self::from_signatures(signatures)
    }
}

fn validate_signature(sig: &TechSignature) -> Result<()> {
    if sig.name.trim().is_empty() {
        anyhow::bail!("signature name cannot be empty");
    }
    if sig.headers.is_empty() && sig.body.is_empty() && sig.path_probes.is_empty() {
        anyhow::bail!("signature {} has no matchers", sig.name);
    }
    for h in &sig.headers {
        if h.name.trim().is_empty() {
            anyhow::bail!("header matcher name cannot be empty");
        }
    }
    for p in &sig.path_probes {
        if !p.path.starts_with('/') {
            anyhow::bail!("path probe must start with '/'");
        }
        if p.status_any_of.is_empty() && p.body_contains.is_empty() {
            anyhow::bail!("path probe requires status_any_of and/or body_contains");
        }
    }
    Ok(())
}

pub fn rank_matches(mut matches: Vec<TechnologyMatch>) -> Vec<TechnologyMatch> {
    matches.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.name.cmp(&b.name))
    });
    matches
}

pub fn detect_from_headers_and_body(
    loaded: &LoadedSignatures,
    headers: &HeaderMap,
    body: &str,
) -> Vec<TechnologyMatch> {
    let lowered_body = body.to_ascii_lowercase();
    let mut out = Vec::new();

    let mut body_match_counts: HashMap<String, u16> = HashMap::new();
    if let Some(ref matcher) = loaded.body_matcher {
        for mat in matcher.find_iter(&lowered_body) {
            let tech_name = &loaded.sig_name_map[mat.pattern()];
            *body_match_counts.entry(tech_name.clone()).or_insert(0) += 1;
        }
    }

    for sig in &loaded.signatures {
        let mut confidence: u16 = 0;
        let mut evidence = Vec::new();

        for hm in &sig.headers {
            if let Some(val) = headers
                .get(hm.name.as_str())
                .and_then(|v| v.to_str().ok())
                .map(|v| v.to_ascii_lowercase())
            {
                let needle = hm.contains.to_ascii_lowercase();
                if val.contains(&needle) {
                    confidence += 35;
                    evidence.push(format!("header:{}~{}", hm.name, hm.contains));
                }
            }
        }

        let matched_count = body_match_counts.get(&sig.name).copied().unwrap_or(0);
        let expected_count = sig.body.len() as u16;
        if matched_count > 0 {
            confidence += (matched_count * 25).min(expected_count * 25);
            for needle in &sig.body {
                evidence.push(format!("body:{}", needle));
            }
        }

        if confidence > 0 {
            out.push(TechnologyMatch {
                name: sig.name.clone(),
                confidence: confidence.min(100) as u8,
                evidence,
                version: None,
                is_dev_mode: false,
            });
        }
    }

    let js_versions = detect_js_version(body);
    for fw in js_versions {
        if !out.iter().any(|m| m.name == fw.name) {
            out.push(TechnologyMatch {
                name: fw.name,
                confidence: 80,
                evidence: vec!["js_framework_detection".to_string()],
                version: fw.version,
                is_dev_mode: fw.is_dev_mode,
            });
        }
    }

    rank_matches(out)
}

pub fn path_probe_matches(probe: &PathProbeSignature, status: u16, body: &str) -> bool {
    let lowered = body.to_ascii_lowercase();
    let status_ok = probe.status_any_of.is_empty() || probe.status_any_of.contains(&status);
    let body_ok = probe.body_contains.is_empty()
        || probe
            .body_contains
            .iter()
            .any(|needle| lowered.contains(&needle.to_ascii_lowercase()));
    status_ok && body_ok
}

pub fn compute_favicon_hash(favicon_data: &[u8]) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    favicon_data.hash(&mut hasher);
    format!("{:x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::{detect_from_headers_and_body, LoadedSignatures, TechSignature};
    use reqwest::header::{HeaderMap, HeaderValue, SERVER};
    use std::fs;

    #[test]
    fn loads_and_validates_signatures() {
        let temp = std::env::temp_dir().join("openxos_signatures_test_load");
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let file = temp.join("tech.json");
        fs::write(
            &file,
            r#"[
                {"name":"nginx","headers":[{"name":"server","contains":"nginx"}]}
            ]"#,
        )
        .unwrap();

        let loaded = LoadedSignatures::load_from_dir(&temp).unwrap();
        assert_eq!(loaded.signatures.len(), 1);
        assert_eq!(loaded.signatures[0].name, "nginx");
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn matches_headers_and_body_with_ranking() {
        let signatures: Vec<TechSignature> = serde_json::from_str(
            r#"[
                {"name":"nginx","headers":[{"name":"server","contains":"nginx"}]},
                {"name":"wordpress","body":["wp-content","wordpress"]}
            ]"#,
        )
        .unwrap();
        let loaded = LoadedSignatures::from_signatures(signatures).unwrap();

        let mut headers = HeaderMap::new();
        headers.insert(SERVER, HeaderValue::from_static("nginx"));
        let matches = detect_from_headers_and_body(&loaded, &headers, "this site has wp-content");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].name, "nginx");
        assert!(matches[0].confidence >= matches[1].confidence);
    }

    #[test]
    fn rejects_invalid_signature_shapes() {
        let temp = std::env::temp_dir().join("openxos_signatures_test_invalid");
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        let file = temp.join("bad.json");
        fs::write(
            &file,
            r#"[
                {"name":"broken","headers":[],"body":[],"path_probes":[]}
            ]"#,
        )
        .unwrap();

        let err = LoadedSignatures::load_from_dir(&temp).unwrap_err();
        let err_str = err.to_string();
        let has_invalid_sig = err_str.contains("invalid signature");
        let has_no_matchers = err_str.contains("has no matchers");
        assert!(
            has_invalid_sig || has_no_matchers,
            "expected error about invalid signature or no matchers, got: {}",
            err_str
        );
        let _ = fs::remove_dir_all(&temp);
    }

    #[test]
    fn path_probe_evaluation_matches_expected() {
        let probe: super::PathProbeSignature = serde_json::from_str(
            r#"{
                "path":"/wp-login.php",
                "status_any_of":[200,302],
                "body_contains":["wordpress"]
            }"#,
        )
        .unwrap();

        assert!(super::path_probe_matches(&probe, 200, "wordpress login"));
        assert!(!super::path_probe_matches(&probe, 404, "wordpress login"));
        assert!(!super::path_probe_matches(&probe, 200, "other"));
    }

    #[test]
    fn path_probe_succeeds_without_status_filter() {
        let probe: super::PathProbeSignature = serde_json::from_str(
            r#"{
                "path":"/admin",
                "body_contains":["login"]
            }"#,
        )
        .unwrap();
        assert!(super::path_probe_matches(&probe, 200, "login page"));
        assert!(super::path_probe_matches(&probe, 403, "login page"));
    }

    #[test]
    fn path_probe_succeeds_without_body_filter() {
        let probe: super::PathProbeSignature = serde_json::from_str(
            r#"{
                "path":"/api/status",
                "status_any_of":[200,204]
            }"#,
        )
        .unwrap();
        assert!(super::path_probe_matches(&probe, 200, "any body"));
        assert!(!super::path_probe_matches(&probe, 404, "any body"));
    }

    #[test]
    fn detect_from_headers_and_body_case_insensitive() {
        let signatures: Vec<TechSignature> = serde_json::from_str(
            r#"[
                {"name":"nginx","headers":[{"name":"server","contains":"nginx"}]}
            ]"#,
        )
        .unwrap();
        let loaded = LoadedSignatures::from_signatures(signatures).unwrap();

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Server",
            reqwest::header::HeaderValue::from_static("NGINX/1.24"),
        );
        let matches = super::detect_from_headers_and_body(&loaded, &headers, "");
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "nginx");
        assert_eq!(matches[0].confidence, 35);
    }

    #[test]
    fn detect_from_headers_and_body_body_match() {
        let signatures: Vec<TechSignature> = serde_json::from_str(
            r#"[
                {"name":"WordPress","body":["wp-content","wp-includes"]}
            ]"#,
        )
        .unwrap();
        let loaded = LoadedSignatures::from_signatures(signatures).unwrap();

        let headers = reqwest::header::HeaderMap::new();
        let matches = super::detect_from_headers_and_body(
            &loaded,
            &headers,
            "This page includes wp-content plugins and wp-includes scripts",
        );
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "WordPress");
        assert_eq!(matches[0].confidence, 50);
    }

    #[test]
    fn detect_from_headers_and_body_no_match() {
        let signatures: Vec<TechSignature> = serde_json::from_str(
            r#"[
                {"name":"nginx","headers":[{"name":"server","contains":"nginx"}]}
            ]"#,
        )
        .unwrap();
        let loaded = LoadedSignatures::from_signatures(signatures).unwrap();

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "Server",
            reqwest::header::HeaderValue::from_static("Apache"),
        );
        let matches = super::detect_from_headers_and_body(&loaded, &headers, "");
        assert!(matches.is_empty());
    }

    #[test]
    fn detect_from_headers_and_body_combined_match() {
        let signatures: Vec<TechSignature> = serde_json::from_str(
            r#"[
                {"name":"nginx","headers":[{"name":"server","contains":"nginx"}]},
                {"name":"php","body":["<?php"]}
            ]"#,
        )
        .unwrap();
        let loaded = LoadedSignatures::from_signatures(signatures).unwrap();

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Server", reqwest::header::HeaderValue::from_static("nginx"));
        let matches = super::detect_from_headers_and_body(&loaded, &headers, "<?php echo 'hello';");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn rank_matches_orders_by_confidence() {
        let mut matches = vec![
            super::TechnologyMatch {
                name: "low".to_string(),
                confidence: 20,
                evidence: vec![],
                version: None,
                is_dev_mode: false,
            },
            super::TechnologyMatch {
                name: "high".to_string(),
                confidence: 90,
                evidence: vec![],
                version: None,
                is_dev_mode: false,
            },
            super::TechnologyMatch {
                name: "medium".to_string(),
                confidence: 55,
                evidence: vec![],
                version: None,
                is_dev_mode: false,
            },
        ];
        let ranked = super::rank_matches(std::mem::take(&mut matches));
        assert_eq!(ranked[0].name, "high");
        assert_eq!(ranked[1].name, "medium");
        assert_eq!(ranked[2].name, "low");
    }

    #[test]
    fn rank_matches_tiebreaker_alphabetical() {
        let mut matches = vec![
            super::TechnologyMatch {
                name: "b-name".to_string(),
                confidence: 50,
                evidence: vec![],
                version: None,
                is_dev_mode: false,
            },
            super::TechnologyMatch {
                name: "a-name".to_string(),
                confidence: 50,
                evidence: vec![],
                version: None,
                is_dev_mode: false,
            },
        ];
        let ranked = super::rank_matches(std::mem::take(&mut matches));
        assert_eq!(ranked[0].name, "a-name");
        assert_eq!(ranked[1].name, "b-name");
    }

    #[test]
    fn compute_favicon_hash_stable() {
        let data = b"test favicon data";
        let hash1 = super::compute_favicon_hash(data);
        let hash2 = super::compute_favicon_hash(data);
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
    }

    #[test]
    fn compute_favicon_hash_different_for_different_content() {
        let hash1 = super::compute_favicon_hash(b"content1");
        let hash2 = super::compute_favicon_hash(b"content2");
        assert_ne!(hash1, hash2);
    }
}
