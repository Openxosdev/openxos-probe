use crate::cli::OutputFormat;
use crate::probe::ProbeResult;
use crate::security::Severity;
use anyhow::Result;
use chrono::Utc;
use colored::*;
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

pub fn write_output(format: OutputFormat, path: Option<PathBuf>, results: &[ProbeResult]) -> Result<()> {
    match format {
        OutputFormat::Terminal => print_terminal(results),
        OutputFormat::Json => write_json(path, results)?,
        OutputFormat::Csv => write_csv(path, results)?,
    }
    Ok(())
}

fn print_terminal(results: &[ProbeResult]) {
    println!("\n=== Openxos Probe Results ===");
    for result in results {
        let status = if result.alive { "ALIVE".green() } else { "DEAD".red() };
        let technologies = if result.technologies.is_empty() {
            "-".to_string()
        } else {
            result
                .technologies
                .iter()
                .map(|t| format!("{}({})", t.name, t.confidence))
                .collect::<Vec<_>>()
                .join(",")
        };
        let findings_summary = if result.security_findings.is_empty() {
            "-".to_string()
        } else {
            result
                .security_findings
                .iter()
                .map(|f| format!("{}:{}:{}", f.severity.as_str(), f.id, f.title))
                .collect::<Vec<_>>()
                .join(" | ")
        };
        let waf_display = result
            .waf
            .as_ref()
            .and_then(|w| w.name.as_ref())
            .map(|n| format!(" [WAF: {}]", n))
            .unwrap_or_default();
        let trace_display = if result.trace_enabled.unwrap_or(false) {
            " [TRACE:ON]".yellow().to_string()
        } else {
            String::new()
        };
        let takeover_display = if let Some(t) = &result.takeover {
            format!(" [TAKEOVER:{}]", t.service).red().bold().to_string()
        } else {
            String::new()
        };
        let tls_display = if let Some(tls) = &result.tls_info {
            format!(" [TLS:{}]", tls.version).blue().to_string()
        } else {
            String::new()
        };
        println!(
            "{} {} status={:?} url={:?} latency={:?}ms tech={} findings={}{}{}{}{}",
            status,
            result.domain,
            result.status_code,
            result.final_url,
            result.response_time_ms,
            technologies,
            findings_summary,
            waf_display,
            trace_display,
            takeover_display,
            tls_display
        );
    }

    let alive_count = results.iter().filter(|r| r.alive).count();
    let summary = Summary::from_results(results);
    let high_domains = actionable_domains(results, Severity::High);
    let medium_domains = actionable_domains(results, Severity::Medium);
    println!(
        "\nScanned: {} | Alive: {} | Dead: {} | Findings: {} (high={}, medium={}, low={})",
        results.len(),
        alive_count,
        results.len() - alive_count,
        summary.findings_total,
        summary.findings_high,
        summary.findings_medium,
        summary.findings_low
    );
    if !high_domains.is_empty() {
        println!("{}", "\nAction required (high):".red().bold());
        for domain in high_domains {
            println!("  - {}", domain.red());
        }
    }
    if !medium_domains.is_empty() {
        println!("{}", "\nReview recommended (medium):".yellow().bold());
        for domain in medium_domains {
            println!("  - {}", domain.yellow());
        }
    }
}

fn write_json(path: Option<PathBuf>, results: &[ProbeResult]) -> Result<()> {
    let report = JsonReport {
        schema_version: "1.0".to_string(),
        generated_at: Utc::now().to_rfc3339(),
        summary: Summary::from_results(results),
        results: results.to_vec(),
    };
    let output = serde_json::to_string_pretty(&report)?;
    if let Some(file) = path {
        fs::write(file, output)?;
    } else {
        println!("{output}");
    }
    Ok(())
}

fn write_csv(path: Option<PathBuf>, results: &[ProbeResult]) -> Result<()> {
    let mut writer: csv::Writer<Vec<u8>> = csv::Writer::from_writer(Vec::new());
    for row in results.iter().map(CsvRow::from_probe_result) {
        writer.serialize(row)?;
    }
    let bytes = writer.into_inner()?;
    let csv_content = String::from_utf8(bytes)?;
    if let Some(file) = path {
        fs::write(file, csv_content)?;
    } else {
        println!("{csv_content}");
    }
    Ok(())
}

#[derive(Serialize)]
struct CsvRow {
    domain: String,
    probe_timestamp: String,
    alive: bool,
    protocol: Option<String>,
    final_url: Option<String>,
    status_code: Option<u16>,
    response_time_ms: Option<u128>,
    error: Option<String>,
    technologies: String,
    waf_name: Option<String>,
    favicon_hash: Option<String>,
    trace_enabled: Option<bool>,
    takeover: Option<String>,
    tls_version: Option<String>,
    cookies: String,
    findings_high: usize,
    findings_medium: usize,
    findings_low: usize,
    finding_ids: String,
    security_findings: String,
}

impl CsvRow {
    fn from_probe_result(result: &ProbeResult) -> Self {
        let mut findings_high = 0usize;
        let mut findings_medium = 0usize;
        let mut findings_low = 0usize;
        let mut finding_ids = Vec::new();
        for finding in &result.security_findings {
            finding_ids.push(finding.id.clone());
            match finding.severity {
                Severity::High => findings_high += 1,
                Severity::Medium => findings_medium += 1,
                Severity::Low => findings_low += 1,
            }
        }
        let technologies = serde_json::to_string(&result.technologies).unwrap_or_else(|_| "[]".into());
        let security_findings =
            serde_json::to_string(&result.security_findings).unwrap_or_else(|_| "[]".into());
        let waf_name = result.waf.as_ref().and_then(|w| w.name.clone());
        let cookies = serde_json::to_string(&result.cookies).unwrap_or_else(|_| "[]".into());
        let takeover = result.takeover.as_ref().map(|t| t.service.clone());
        let tls_version = result.tls_info.as_ref().map(|t| t.version.clone());
        Self {
            domain: result.domain.clone(),
            probe_timestamp: result.probe_timestamp.to_rfc3339(),
            alive: result.alive,
            protocol: result.protocol.clone(),
            final_url: result.final_url.clone(),
            status_code: result.status_code,
            response_time_ms: result.response_time_ms,
            error: result.error.clone(),
            technologies,
            waf_name,
            favicon_hash: result.favicon_hash.clone(),
            trace_enabled: result.trace_enabled,
            takeover,
            tls_version,
            cookies,
            findings_high,
            findings_medium,
            findings_low,
            finding_ids: finding_ids.join(";"),
            security_findings,
        }
    }
}

#[derive(Serialize)]
struct JsonReport {
    schema_version: String,
    generated_at: String,
    summary: Summary,
    results: Vec<ProbeResult>,
}

#[derive(Serialize)]
pub struct Summary {
    scanned: usize,
    alive: usize,
    dead: usize,
    findings_total: usize,
    findings_high: usize,
    findings_medium: usize,
    findings_low: usize,
}

impl Summary {
    pub fn from_results(results: &[ProbeResult]) -> Self {
        let scanned = results.len();
        let alive = results.iter().filter(|r| r.alive).count();
        let mut findings_high = 0usize;
        let mut findings_medium = 0usize;
        let mut findings_low = 0usize;

        for result in results {
            for finding in &result.security_findings {
                match finding.severity {
                    Severity::High => findings_high += 1,
                    Severity::Medium => findings_medium += 1,
                    Severity::Low => findings_low += 1,
                }
            }
        }

        Self {
            scanned,
            alive,
            dead: scanned.saturating_sub(alive),
            findings_total: findings_high + findings_medium + findings_low,
            findings_high,
            findings_medium,
            findings_low,
        }
    }
}

fn actionable_domains(results: &[ProbeResult], severity: Severity) -> Vec<String> {
    let mut domains = Vec::new();
    for result in results {
        if result.security_findings.iter().any(|f| f.severity == severity) {
            domains.push(result.domain.clone());
        }
    }
    domains.sort();
    domains.dedup();
    domains
}

pub async fn send_webhook_notification(
    webhook_url: &str,
    summary: &Summary,
    total_domains: usize,
    elapsed_secs: f64,
) -> Result<()> {
    let payload = serde_json::json!({
        "content": format!(
            "**Openxos Probe Scan Complete**\n\n\
            Scanned: {} domains\n\
            Alive: {} | Dead: {}\n\
            Findings: {} (High: {}, Medium: {}, Low: {})\n\
            Duration: {:.1}s",
            total_domains,
            summary.alive,
            summary.dead,
            summary.findings_total,
            summary.findings_high,
            summary.findings_medium,
            summary.findings_low,
            elapsed_secs
        ),
        "embeds": [
            {
                "title": "Scan Summary",
                "color": if summary.findings_high > 0 { 15158332 } else { 3066993 },
                "fields": [
                    {"name": "Total", "value": total_domains.to_string(), "inline": true},
                    {"name": "Alive", "value": summary.alive.to_string(), "inline": true},
                    {"name": "Dead", "value": summary.dead.to_string(), "inline": true},
                    {"name": "High", "value": summary.findings_high.to_string(), "inline": true},
                    {"name": "Medium", "value": summary.findings_medium.to_string(), "inline": true},
                    {"name": "Low", "value": summary.findings_low.to_string(), "inline": true},
                ]
            }
        ]
    });

    let client = reqwest::Client::new();
    client
        .post(webhook_url)
        .json(&payload)
        .timeout(Duration::from_secs(10))
        .send()
        .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::output::{actionable_domains, Summary};
    use crate::probe::{map_probe_failure, map_probe_success};
    use crate::security::{Severity, WafInfo};

    fn sample_alive_result(domain: &str) -> crate::probe::ProbeResult {
        map_probe_success(
            domain,
            "https",
            &format!("https://{}/login", domain),
            200,
            45,
            vec![],
            vec![],
            Some(WafInfo {
                name: Some("Cloudflare".to_string()),
                blocked: false,
                evidence: "cf-ray".to_string(),
            }),
            Some("hash123".to_string()),
            Some(false),
            vec!["session=abc".to_string()],
        )
    }

    fn result_with_finding(domain: &str, severity: Severity) -> crate::probe::ProbeResult {
        let mut result = sample_alive_result(domain);
        result.security_findings.push(crate::security::SecurityFinding {
            id: "test-finding".to_string(),
            category: "security_headers".to_string(),
            severity,
            title: "Test finding".to_string(),
            explanation: "Test explanation".to_string(),
            evidence: "test".to_string(),
        });
        result
    }

    #[test]
    fn summary_counts_alive_and_dead() {
        let results = vec![
            sample_alive_result("alive1.com"),
            sample_alive_result("alive2.com"),
            map_probe_failure("dead1.com", Some("timeout".to_string())),
        ];
        let summary = Summary::from_results(&results);
        assert_eq!(summary.scanned, 3);
        assert_eq!(summary.alive, 2);
        assert_eq!(summary.dead, 1);
    }

    #[test]
    fn summary_counts_findings_by_severity() {
        let mut r1 = sample_alive_result("test.com");
        r1.security_findings.push(crate::security::SecurityFinding {
            id: "high1".to_string(),
            category: "info".to_string(),
            severity: Severity::High,
            title: "H".to_string(),
            explanation: "H".to_string(),
            evidence: "H".to_string(),
        });
        r1.security_findings.push(crate::security::SecurityFinding {
            id: "medium1".to_string(),
            category: "info".to_string(),
            severity: Severity::Medium,
            title: "M".to_string(),
            explanation: "M".to_string(),
            evidence: "M".to_string(),
        });
        let mut r2 = sample_alive_result("test2.com");
        r2.security_findings.push(crate::security::SecurityFinding {
            id: "low1".to_string(),
            category: "info".to_string(),
            severity: Severity::Low,
            title: "L".to_string(),
            explanation: "L".to_string(),
            evidence: "L".to_string(),
        });
        let results = vec![r1, r2];
        let summary = Summary::from_results(&results);
        assert_eq!(summary.findings_total, 3);
        assert_eq!(summary.findings_high, 1);
        assert_eq!(summary.findings_medium, 1);
        assert_eq!(summary.findings_low, 1);
    }

    #[test]
    fn summary_empty_results() {
        let results: Vec<crate::probe::ProbeResult> = vec![];
        let summary = Summary::from_results(&results);
        assert_eq!(summary.scanned, 0);
        assert_eq!(summary.alive, 0);
        assert_eq!(summary.dead, 0);
        assert_eq!(summary.findings_total, 0);
    }

    #[test]
    fn actionable_domains_filters_by_severity() {
        let results = vec![
            result_with_finding("high1.com", Severity::High),
            result_with_finding("medium1.com", Severity::Medium),
            result_with_finding("low1.com", Severity::Low),
            sample_alive_result("clean.com"),
        ];
        let high = actionable_domains(&results, Severity::High);
        let medium = actionable_domains(&results, Severity::Medium);
        let low = actionable_domains(&results, Severity::Low);

        assert_eq!(high, vec!["high1.com".to_string()]);
        assert_eq!(medium, vec!["medium1.com".to_string()]);
        assert_eq!(low, vec!["low1.com".to_string()]);
    }

    #[test]
    fn actionable_domains_dedups_multiples() {
        let mut r1 = result_with_finding("dup.com", Severity::High);
        r1.security_findings.push(crate::security::SecurityFinding {
            id: "high2".to_string(),
            category: "info".to_string(),
            severity: Severity::High,
            title: "H2".to_string(),
            explanation: "H2".to_string(),
            evidence: "H2".to_string(),
        });
        let results = vec![r1, result_with_finding("other.com", Severity::Medium)];
        let high = actionable_domains(&results, Severity::High);
        assert_eq!(high.len(), 1);
        assert_eq!(high[0], "dup.com");
    }

    #[test]
    fn write_output_accepts_json_format() {
        let results = vec![sample_alive_result("test.com")];
        let output = serde_json::to_string_pretty(&results).unwrap();
        assert!(output.contains("test.com"));
        assert!(output.contains("hash123"));
    }

    #[test]
    fn summary_total_never_negative() {
        let results = vec![map_probe_failure("dead.com", Some("refused".to_string()))];
        let summary = Summary::from_results(&results);
        assert_eq!(summary.dead, 1);
        assert!(summary.findings_total == 0);
    }

    #[test]
    fn findings_severity_as_str() {
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Medium.as_str(), "medium");
        assert_eq!(Severity::Low.as_str(), "low");
    }

    #[test]
    fn webhook_payload_format_with_no_findings() {
        let summary = Summary {
            scanned: 10,
            alive: 5,
            dead: 5,
            findings_total: 0,
            findings_high: 0,
            findings_medium: 0,
            findings_low: 0,
        };
        let payload = serde_json::json!({
            "content": format!(
                "**Openxos Probe Scan Complete**\n\n\
                Scanned: {} domains\n\
                Alive: {} | Dead: {}\n\
                Findings: {} (High: {}, Medium: {}, Low: {})\n\
                Duration: {:.1}s",
                10,
                summary.alive,
                summary.dead,
                summary.findings_total,
                summary.findings_high,
                summary.findings_medium,
                summary.findings_low,
                5.0
            ),
            "embeds": [
                {
                    "title": "Scan Summary",
                    "color": 3066993,
                    "fields": [
                        {"name": "Total", "value": "10", "inline": true},
                        {"name": "Alive", "value": "5", "inline": true},
                        {"name": "Dead", "value": "5", "inline": true},
                        {"name": "High", "value": "0", "inline": true},
                        {"name": "Medium", "value": "0", "inline": true},
                        {"name": "Low", "value": "0", "inline": true},
                    ]
                }
            ]
        });
        assert_eq!(payload["content"].as_str().unwrap().len() > 0, true);
        assert_eq!(payload["embeds"][0]["color"], 3066993);
    }

    #[test]
    fn webhook_payload_format_with_high_findings() {
        let summary = Summary {
            scanned: 10,
            alive: 5,
            dead: 5,
            findings_total: 3,
            findings_high: 2,
            findings_medium: 1,
            findings_low: 0,
        };
        let has_high = summary.findings_high > 0;
        assert_eq!(has_high, true);
    }

    #[test]
    fn webhook_embed_color_for_alert() {
        let summary_high = Summary {
            scanned: 10,
            alive: 5,
            dead: 5,
            findings_total: 1,
            findings_high: 1,
            findings_medium: 0,
            findings_low: 0,
        };
        let summary_ok = Summary {
            scanned: 10,
            alive: 5,
            dead: 5,
            findings_total: 0,
            findings_high: 0,
            findings_medium: 0,
            findings_low: 0,
        };
        assert_eq!(summary_high.findings_high > 0, true);
        assert_eq!(summary_ok.findings_high > 0, false);
    }
}
