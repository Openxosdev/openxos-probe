use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::LazyLock;
use url::Url;

static IPV4_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^(\d{1,3}\.){3}\d{1,3}$").unwrap());

static IPV6_REGEX: LazyLock<regex::Regex> = LazyLock::new(|| regex::Regex::new(r":.*:").unwrap());

static LABEL_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$").unwrap());

static HOSTNAME_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$").unwrap());

static INVALID_CHARS_REGEX: LazyLock<regex::Regex> =
    LazyLock::new(|| regex::Regex::new(r"[^\x20-\x7E]").unwrap());

static SINKHOLE_DOMAINS: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    HashSet::from([
        "localhost",
        "localhost.localdomain",
        "local",
        "invalid",
        "test",
        "example",
        "example.com",
        "example.org",
        "example.net",
        "test.com",
        "localhost.com",
    ])
});

static RESERVED_DOMAINS: LazyLock<HashSet<&'static str>> =
    LazyLock::new(|| HashSet::from(["0.0.0.0", "255.255.255.255", "127.0.0.1", "::1", "fe80::1"]));

#[derive(Debug, Clone)]
pub struct DomainValidationStats {
    pub total_lines: usize,
    pub skipped_empty: usize,
    pub skipped_comments: usize,
    pub skipped_invalid: usize,
    pub skipped_duplicates: usize,
    pub skipped_sinkhole: usize,
    pub skipped_reserved: usize,
    pub valid_domains: usize,
}

pub struct DomainParseResult {
    pub domains: Vec<String>,
    pub stats: DomainValidationStats,
}

#[allow(dead_code)]
pub fn load_domains(input: &Path) -> Result<Vec<String>> {
    let content =
        fs::read_to_string(input).with_context(|| format!("failed to read {:?}", input))?;
    Ok(parse_domains(&content).domains)
}

pub fn parse_domains(content: &str) -> DomainParseResult {
    let mut stats = DomainValidationStats {
        total_lines: 0,
        skipped_empty: 0,
        skipped_comments: 0,
        skipped_invalid: 0,
        skipped_duplicates: 0,
        skipped_sinkhole: 0,
        skipped_reserved: 0,
        valid_domains: 0,
    };

    let mut seen = HashSet::new();
    let mut domains = Vec::new();

    for line in content.lines() {
        stats.total_lines += 1;
        let trimmed = line.trim();

        if trimmed.is_empty() {
            stats.skipped_empty += 1;
            continue;
        }

        if trimmed.starts_with('#') {
            stats.skipped_comments += 1;
            continue;
        }

        let Some(normalized) = normalize_domain(trimmed) else {
            stats.skipped_invalid += 1;
            continue;
        };

        if SINKHOLE_DOMAINS.contains(normalized.as_str()) {
            stats.skipped_sinkhole += 1;
            continue;
        }

        if RESERVED_DOMAINS.contains(normalized.as_str()) {
            stats.skipped_reserved += 1;
            continue;
        }

        if !seen.insert(normalized.clone()) {
            stats.skipped_duplicates += 1;
            continue;
        }

        stats.valid_domains += 1;
        domains.push(normalized);
    }

    DomainParseResult { domains, stats }
}

pub fn normalize_domain(raw: &str) -> Option<String> {
    let without_fragment = raw.split('#').next()?.trim();

    if without_fragment.is_empty() {
        return None;
    }

    if without_fragment.contains(':') && !without_fragment.contains("://") {
        let parts: Vec<&str> = without_fragment.split(':').collect();
        if parts.len() == 2 && parts[1].parse::<u16>().is_ok() {
            return None;
        }
    }

    let parsed = if without_fragment.contains("://") {
        Url::parse(without_fragment).ok()?
    } else {
        Url::parse(&format!("https://{without_fragment}")).ok()?
    };

    if parsed.port().is_some() {
        return None;
    }

    let host = parsed.host_str()?.to_ascii_lowercase();

    if host.starts_with('.') || host.ends_with('.') {
        return None;
    }

    if host.contains(' ') {
        return None;
    }

    if host.is_empty() {
        return None;
    }

    if host == "localhost" || host == "local" {
        return None;
    }

    if IPV4_REGEX.is_match(&host) {
        return validate_ipv4(&host);
    }

    if IPV6_REGEX.is_match(&host) {
        return validate_ipv6(&host);
    }

    if !host.contains('.') && !host.eq("localhost") {
        return None;
    }

    validate_hostname(&host)
}

fn validate_ipv4(host: &str) -> Option<String> {
    let octets: Vec<&str> = host.split('.').collect();

    if octets.len() != 4 {
        return None;
    }

    for octet in &octets {
        let value: u32 = octet.parse().ok()?;

        if value > 255 {
            return None;
        }
    }

    let first_octet: u32 = octets[0].parse().ok()?;

    if first_octet == 0
        || first_octet == 127
        || (224..=239).contains(&first_octet)
        || first_octet >= 240
    {
        return None;
    }

    if host == "0.0.0.0" {
        return None;
    }

    Some(host.to_string())
}

fn validate_ipv6(host: &str) -> Option<String> {
    if host == "::1" || host == "fe80::1" {
        return None;
    }

    Some(host.to_string())
}

fn validate_hostname(host: &str) -> Option<String> {
    let trimmed = host.trim_start_matches('.').trim_end_matches('.').trim();

    if trimmed.is_empty() {
        return None;
    }

    if trimmed.len() > 253 {
        return None;
    }

    if !HOSTNAME_REGEX.is_match(trimmed) {
        return None;
    }

    if INVALID_CHARS_REGEX.is_match(trimmed) {
        return None;
    }

    if trimmed.starts_with("xn--") {
        return Some(trimmed.to_string());
    }

    if trimmed.starts_with('-') || trimmed.ends_with('-') {
        return None;
    }

    let labels: Vec<&str> = trimmed.split('.').collect();

    if labels.len() > 127 {
        return None;
    }

    for label in &labels {
        if label.is_empty() {
            return None;
        }

        if label.len() > 63 {
            return None;
        }

        if !LABEL_REGEX.is_match(label) {
            return None;
        }
    }

    let tld = labels.last().unwrap_or(&"");

    if tld.len() < 2 {
        return None;
    }

    Some(trimmed.to_string())
}

#[allow(dead_code)]
pub fn is_valid_subdomain(domain: &str, base_domain: &str) -> bool {
    let domain_lower = domain.to_ascii_lowercase();
    let base_lower = base_domain.to_ascii_lowercase();

    if domain_lower == base_lower {
        return false;
    }

    domain_lower.ends_with(&format!(".{}", base_lower))
}

#[allow(dead_code)]
pub fn categorize_domain(domain: &str) -> DomainCategory {
    let lower = domain.to_ascii_lowercase();

    if IPV4_REGEX.is_match(&lower) || IPV6_REGEX.is_match(&lower) {
        return DomainCategory::IpAddress;
    }

    let labels: Vec<&str> = lower.split('.').collect();

    if labels.len() == 1 {
        return DomainCategory::SingleLabel;
    }

    let tld = *labels.last().unwrap_or(&"");

    match tld {
        "io" | "ai" | "tech" | "dev" | "app" | "cloud" | "security" | "cyber" => {
            DomainCategory::TechTld
        }
        "xyz" | "top" | "club" | "online" | "site" | "website" | "space" | "work" | "fun" => {
            DomainCategory::CheapTld
        }
        "info" | "biz" | "name" | "pro" | "mobi" | "tel" => DomainCategory::GenericTld,
        "org" | "net" | "edu" | "gov" | "mil" => DomainCategory::OrgTld,
        "com" | "co" | "uk" | "de" | "fr" | "jp" | "cn" | "ru" | "br" | "in" | "au" | "ca" => {
            DomainCategory::CommercialTld
        }
        _ => DomainCategory::OtherTld,
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainCategory {
    IpAddress,
    SingleLabel,
    CommercialTld,
    TechTld,
    CheapTld,
    GenericTld,
    OrgTld,
    OtherTld,
}

#[allow(dead_code)]
impl DomainCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            DomainCategory::IpAddress => "ip-address",
            DomainCategory::SingleLabel => "single-label",
            DomainCategory::CommercialTld => "commercial-tld",
            DomainCategory::TechTld => "tech-tld",
            DomainCategory::CheapTld => "cheap-tld",
            DomainCategory::GenericTld => "generic-tld",
            DomainCategory::OrgTld => "org-tld",
            DomainCategory::OtherTld => "other-tld",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        categorize_domain, is_valid_subdomain, normalize_domain, parse_domains, DomainCategory,
    };

    #[test]
    fn parses_comments_duplicates_and_urls() {
        let content = r#"
            # leading comment
            google.com
            https://github.com/path?q=1
            http://amazon.com
            invalid host
            localhost
            github.com#inline-comment
            github.com
        "#;

        let result = parse_domains(content);
        assert_eq!(result.domains.len(), 3);
        assert_eq!(result.stats.skipped_comments, 1);
        assert_eq!(result.stats.skipped_invalid, 2);
        assert_eq!(result.stats.skipped_sinkhole, 0);
        assert_eq!(result.stats.skipped_duplicates, 2);
    }

    #[test]
    fn rejects_invalid_domains() {
        assert!(normalize_domain("").is_none());
        assert!(normalize_domain("localhost").is_none());
        assert!(normalize_domain("-example.com").is_none());
        assert!(normalize_domain("example-.com").is_none());
        assert!(normalize_domain(".example.com").is_none());
        assert!(normalize_domain("example.com.").is_none());
        assert!(normalize_domain("example..com").is_none());
        assert!(normalize_domain("127.0.0.1").is_none());
        assert!(normalize_domain("::1").is_none());
    }

    #[test]
    fn normalizes_valid_domains() {
        assert_eq!(
            normalize_domain("EXAMPLE.COM"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_domain("https://api.example.com/"),
            Some("api.example.com".to_string())
        );
        assert_eq!(
            normalize_domain("http://TEST.COM/path"),
            Some("test.com".to_string())
        );
    }

    #[test]
    fn removes_duplicates() {
        let content = "google.com\ngoogle.com\nmicrosoft.com";
        let result = parse_domains(content);
        assert_eq!(result.domains.len(), 2);
        assert_eq!(result.stats.skipped_duplicates, 1);
    }

    #[test]
    fn handles_label_length_limit() {
        let long_label = "a".repeat(64);
        assert!(normalize_domain(&format!("{}.com", long_label)).is_none());
        assert!(normalize_domain(&format!("{}.com", "a".repeat(63))).is_some());
    }

    #[test]
    fn validates_ipv4_addresses() {
        assert!(normalize_domain("8.8.8.8").is_some());
        assert!(normalize_domain("1.1.1.1").is_some());
        assert!(normalize_domain("192.168.1.1").is_some());
        assert!(normalize_domain("256.1.1.1").is_none());
        assert!(normalize_domain("0.0.0.0").is_none());
        assert!(normalize_domain("127.0.0.1").is_none());
        assert!(normalize_domain("224.0.0.1").is_none());
    }

    #[test]
    fn validates_ipv6_addresses() {
        assert!(normalize_domain("::1").is_none());
        assert!(normalize_domain("fe80::1").is_none());
    }

    #[test]
    fn subdomain_validation() {
        assert!(is_valid_subdomain("www.example.com", "example.com"));
        assert!(is_valid_subdomain("api.example.com", "example.com"));
        assert!(!is_valid_subdomain("example.com", "example.com"));
        assert!(!is_valid_subdomain("notexample.com", "example.com"));
        assert!(is_valid_subdomain("deep.nested.example.com", "example.com"));
        assert!(!is_valid_subdomain("fakeexample.com", "example.com"));
    }

    #[test]
    fn domain_categorization() {
        assert_eq!(
            categorize_domain("example.com"),
            DomainCategory::CommercialTld
        );
        assert_eq!(categorize_domain("api.tech.io"), DomainCategory::TechTld);
        assert_eq!(categorize_domain("example.xyz"), DomainCategory::CheapTld);
        assert_eq!(categorize_domain("8.8.8.8"), DomainCategory::IpAddress);
        assert_eq!(
            categorize_domain("example.unknown"),
            DomainCategory::OtherTld
        );
        assert_eq!(categorize_domain("example.org"), DomainCategory::OrgTld);
        assert_eq!(categorize_domain("example.net"), DomainCategory::OrgTld);
        assert_eq!(categorize_domain("example.edu"), DomainCategory::OrgTld);
    }

    #[test]
    fn tracks_validation_stats() {
        let content = "# comment\n\n.example.com\ngmail.com\ngmail.com\n127.0.0.1";
        let result = parse_domains(content);

        assert_eq!(result.stats.total_lines, 6);
        assert_eq!(result.stats.skipped_comments, 1);
        assert_eq!(result.stats.skipped_empty, 1);
        assert_eq!(result.stats.skipped_invalid, 2);
        assert_eq!(result.stats.skipped_reserved, 0);
        assert_eq!(result.stats.skipped_duplicates, 1);
        assert_eq!(result.stats.valid_domains, 1);
    }

    #[test]
    fn handles_whitespace_in_domains() {
        assert!(normalize_domain("  example.com  ").is_some());
        assert!(normalize_domain("\texample.com\n").is_some());
    }

    #[test]
    fn rejects_empty_octets_in_ipv4() {
        assert!(normalize_domain("1.2.3..5").is_none());
        assert!(normalize_domain("1..3.4").is_none());
    }

    #[test]
    fn rejects_leading_trailing_dots() {
        assert!(normalize_domain(".example.com").is_none());
        assert!(normalize_domain("example.com.").is_none());
    }

    #[test]
    fn normalizes_https_urls() {
        assert_eq!(
            normalize_domain("https://Example.COM/"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn normalizes_http_urls() {
        assert_eq!(
            normalize_domain("http://test.COM/path"),
            Some("test.com".to_string())
        );
    }

    #[test]
    fn strips_fragment_and_query() {
        assert_eq!(
            normalize_domain("https://example.com/page?q=1#section"),
            Some("example.com".to_string())
        );
        assert_eq!(
            normalize_domain("https://example.com/page#anchor"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn rejects_domains_with_port() {
        assert!(normalize_domain("example.com:8080").is_none());
        assert!(normalize_domain("192.168.1.1:443").is_none());
    }

    #[test]
    fn handles_full_width_chars() {
        assert!(normalize_domain(
            "\u{FF21}\u{FF25}\u{FF38}\u{FF34}\u{FF2F}\u{FF2C}\u{FF2F}\u{FF2D}"
        )
        .is_none());
    }

    #[test]
    fn parse_domains_tracks_all_stats() {
        let content =
            "# comment line\n\n\ninvalid!@#\ngithub.com\ngithub.com\ngoogle.com\n127.0.0.1";
        let result = parse_domains(content);

        assert_eq!(result.stats.total_lines, 8);
        assert_eq!(result.stats.skipped_comments, 1);
        assert_eq!(result.stats.skipped_empty, 2);
        assert_eq!(result.stats.skipped_invalid, 2);
        assert_eq!(result.stats.skipped_reserved, 0);
        assert_eq!(result.stats.skipped_duplicates, 1);
        assert_eq!(result.stats.skipped_sinkhole, 0);
        assert_eq!(result.stats.valid_domains, 2);
        assert_eq!(result.domains, vec!["github.com", "google.com"]);
    }
}
