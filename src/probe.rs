use crate::config::AppConfig;
use crate::security::{
    analyze_cookies, analyze_information_disclosure, analyze_redirect, analyze_security_headers,
    check_trace_method, detect_cloud_provider, detect_waf, CacheAnalysis, ContentTypeMismatch,
    CookieInfo, ExposedPathObservation, MethodEnumerationResult, RateLimitInfo, RedirectInfo,
    SecurityFinding, Severity, WafInfo,
};
use crate::technology::{
    detect_from_headers_and_body, path_probe_matches, rank_matches, LoadedSignatures,
    TechnologyMatch,
};
use crate::tls_analysis::TlsInfo;
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use reqwest::header::USER_AGENT;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use url::Url;

#[derive(Debug, Clone, Serialize)]
pub struct ApiDocInfo {
    pub path: String,
    pub doc_type: String,
    pub title: Option<String>,
    pub version: Option<String>,
    pub endpoint_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct WebSocketInfo {
    pub path: String,
    pub status: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolResult {
    pub url: String,
    pub status_code: u16,
    pub response_time_ms: u128,
    pub technologies: Vec<TechnologyMatch>,
    pub security_findings: Vec<SecurityFinding>,
    pub waf: Option<WafInfo>,
    pub favicon_hash: Option<String>,
    pub trace_enabled: bool,
    pub cookies: Vec<String>,
    pub detailed_cookies: Vec<CookieInfo>,
    pub redirect_info: Option<RedirectInfo>,
    pub http_version: Option<String>,
    pub http3_advertised: bool,
    pub http3_port: Option<u16>,
    pub websocket: Option<WebSocketInfo>,
    pub graphql: Option<GraphQLInfo>,
    pub api_docs: Vec<ApiDocInfo>,
    pub cloud_info: Option<super::security::CloudInfo>,
    pub ssrf_info: Option<SsrfVectorInfo>,
    pub tls_info: Option<TlsInfo>,
    pub takeover: Option<TakeoverFinding>,
    pub content_type_mismatch: Option<ContentTypeMismatch>,
    pub timing: Option<TimingStats>,
    pub allowed_http_methods: Vec<String>,
    pub dangerous_http_methods: Vec<String>,
    pub rate_limit: Option<RateLimitInfo>,
    pub cache: Option<CacheAnalysis>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphQLInfo {
    pub endpoint: String,
    pub introspection_enabled: bool,
    pub has_mutations: bool,
    pub has_subscriptions: bool,
    pub graphiql_available: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TimingStats {
    pub ttfb_ms: u64,
    pub total_ms: u64,
    pub download_speed_bps: Option<u64>,
}

impl TimingStats {
    #[allow(dead_code)]
    pub fn new(ttfb: Duration, total: Duration, content_length: Option<u64>) -> Self {
        let download_speed = content_length.map(|len| {
            let total_secs = total.as_secs_f64();
            if total_secs > 0.0 {
                (len as f64 / total_secs) as u64
            } else {
                0
            }
        });

        Self {
            ttfb_ms: ttfb.as_millis() as u64,
            total_ms: total.as_millis() as u64,
            download_speed_bps: download_speed,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CertificateTransparencyInfo {
    pub subdomains: Vec<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct SsrfVectorInfo {
    pub vulnerable_parameters: Vec<String>,
    pub checked_at: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    pub domain: String,
    pub probe_timestamp: DateTime<Utc>,
    pub alive: bool,
    pub protocol: Option<String>,
    pub final_url: Option<String>,
    pub status_code: Option<u16>,
    pub response_time_ms: Option<u128>,
    pub error: Option<String>,
    pub technologies: Vec<TechnologyMatch>,
    pub security_findings: Vec<SecurityFinding>,
    pub waf: Option<WafInfo>,
    pub favicon_hash: Option<String>,
    pub trace_enabled: Option<bool>,
    pub cookies: Vec<String>,
    pub redirect_info: Option<RedirectInfo>,
    pub detailed_cookies: Vec<CookieInfo>,
    pub http_result: Option<ProtocolResult>,
    pub https_result: Option<ProtocolResult>,
    pub ct_info: Option<CertificateTransparencyInfo>,
    pub cloud_info: Option<super::security::CloudInfo>,
    pub ssrf_info: Option<SsrfVectorInfo>,
    pub takeover: Option<TakeoverFinding>,
    pub content_type_mismatch: Option<ContentTypeMismatch>,
    pub allowed_http_methods: Vec<String>,
    pub dangerous_http_methods: Vec<String>,
    pub rate_limit: Option<RateLimitInfo>,
    pub cache: Option<CacheAnalysis>,
    pub tls_info: Option<TlsInfo>,
    pub timing: Option<TimingStats>,
}

#[derive(Debug, Clone)]
pub struct ProbeConfig {
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub retries: u8,
    pub user_agent: String,
    pub insecure: bool,
    pub signatures: LoadedSignatures,
    pub ct_logs: bool,
    pub fast: bool,
    pub aggressive: bool,
}

fn load_signatures_with_fallback() -> Result<LoadedSignatures> {
    let mut search_paths = vec![std::path::PathBuf::from("signatures")];

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            search_paths.push(parent.join("signatures"));
        }
    }

    if let Ok(var) = std::env::var("OPENXOS_SIGNATURES") {
        search_paths.push(std::path::PathBuf::from(var));
    }

    for path in search_paths {
        if path.exists() {
            match LoadedSignatures::load_from_dir(&path) {
                Ok(sigs) if !sigs.signatures.is_empty() => return Ok(sigs),
                _ => continue,
            }
        }
    }

    Ok(LoadedSignatures::from_signatures(vec![])?)
}

impl ProbeConfig {
    pub fn from_config(config: &AppConfig) -> Result<Self> {
        let signatures = load_signatures_with_fallback()?;
        if signatures.signatures.is_empty() {
            eprintln!("Warning: No technology signatures loaded.");
            eprintln!("  Create a 'signatures/' directory with .json files,");
            eprintln!("  or set OPENXOS_SIGNATURES env var to the signatures directory.");
        }
        Ok(Self {
            concurrency: config.concurrency.clamp(1, 500),
            timeout_secs: config.timeout_secs.clamp(1, 300),
            retries: config.retries,
            user_agent: config.user_agent.clone(),
            insecure: config.insecure,
            signatures,
            ct_logs: config.ct_logs,
            fast: config.fast,
            aggressive: config.aggressive,
        })
    }
}

static DNS_CACHE: std::sync::LazyLock<DashMap<String, (Vec<IpAddr>, Instant)>> =
    std::sync::LazyLock::new(DashMap::new);

const DNS_TTL: Duration = Duration::from_secs(300);

#[allow(dead_code)]
const TAKEOVER_SIGNATURES: &[(&str, &str, &str)] = &[
    (
        "There is no app configured at that hostname",
        "Heroku",
        "heroku",
    ),
    ("No such app", "Heroku", "heroku"),
    ("404 - Page Not Found", "GitHub Pages", "github-pages"),
    ("The specified bucket does not exist", "AWS S3", "aws-s3"),
    ("NoSuchBucket", "AWS S3", "aws-s3"),
    ("<Code>NoSuchBucket</Code>", "AWS S3", "aws-s3"),
    ("Repository not found", "Bitbucket", "bitbucket"),
    ("Project not found", "GitLab", "gitlab"),
    ("is not a registered domain", "Vercel", "vercel"),
    ("doesn't exist", "Netlify", "netlify"),
    ("is not configured to handle requests", "Shopify", "shopify"),
    ("doesn't have any DNS records", "Squarespace", "squarespace"),
];

#[derive(Debug, Clone, Serialize)]
pub struct TakeoverFinding {
    pub domain: String,
    pub service: String,
    pub fingerprint: String,
}

#[allow(dead_code)]
pub async fn check_takeover(domain: &str, status: u16, body: &str) -> Option<TakeoverFinding> {
    if status == 200 {
        return None;
    }

    let body_lower = body.to_lowercase();

    for (fingerprint, service, _) in TAKEOVER_SIGNATURES {
        if body_lower.contains(&fingerprint.to_lowercase()) {
            return Some(TakeoverFinding {
                domain: domain.to_string(),
                service: service.to_string(),
                fingerprint: fingerprint.to_string(),
            });
        }
    }
    None
}

async fn resolve_dns_cached(domain: &str) -> Option<Vec<IpAddr>> {
    {
        if let Some(entry) = DNS_CACHE.get(domain) {
            let (ips, cached_at) = entry.value();
            if cached_at.elapsed() < DNS_TTL {
                return Some(ips.clone());
            }
        }
    }

    let ips = tokio::net::lookup_host(format!("{}:443", domain))
        .await
        .ok()?
        .map(|addr| addr.ip())
        .collect::<Vec<_>>();

    if !ips.is_empty() {
        DNS_CACHE.insert(domain.to_string(), (ips.clone(), Instant::now()));
    }

    Some(ips)
}

pub async fn probe_domains<F>(
    domains: Vec<String>,
    config: ProbeConfig,
    mut on_result: F,
) -> Result<Vec<ProbeResult>>
where
    F: FnMut(usize, &ProbeResult),
{
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(config.insecure)
        .redirect(reqwest::redirect::Policy::limited(10))
        .tcp_nodelay(true)
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(90))
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(config.timeout_secs))
        .build()
        .context("failed to build HTTP client")?;

    let total = domains.len();
    let shared = Arc::new(config);

    let results = stream::iter(domains.into_iter().enumerate())
        .map(|(idx, domain)| {
            let client = client.clone();
            let config = Arc::clone(&shared);
            async move {
                let result = probe_domain(&client, &domain, &config).await;
                (idx + 1, result)
            }
        })
        .buffer_unordered(shared.concurrency)
        .map(|(done, result)| {
            on_result(done, &result);
            result
        })
        .collect::<Vec<_>>()
        .await;

    if results.len() != total {
        anyhow::bail!("probe result count mismatch");
    }

    Ok(results)
}

fn parse_alt_svc(header: &str) -> (bool, Option<u16>) {
    let mut advertised = false;
    let mut port = None;

    for part in header.split(',') {
        let part = part.trim();
        if part.starts_with("h3=") {
            advertised = true;
            if let Some(start) = part.find('"') {
                let rest = &part[start + 1..];
                if let Some(end) = rest.find('"') {
                    let value = &rest[..end];
                    if let Some(colon) = value.find(':') {
                        port = value[colon + 1..].parse().ok();
                    }
                }
            }
            break;
        }
    }
    (advertised, port)
}

async fn probe_protocol(
    client: &reqwest::Client,
    domain: &str,
    scheme: &str,
    config: &ProbeConfig,
) -> (Option<ProtocolResult>, Option<String>) {
    let target = format!("{scheme}://{domain}");
    let mut last_error: Option<String> = None;

    for attempt in 0..config.retries {
        let request_started = Instant::now();
        let response = client
            .get(&target)
            .header(USER_AGENT, &config.user_agent)
            .send()
            .await;

        match response {
            Ok(resp) => {
                let network_time_ms = request_started.elapsed().as_millis();
                let final_url = resp.url().as_str().to_string();
                let status_code = resp.status().as_u16();
                let headers = resp.headers().clone();
                let version = resp.version();
                let http_version = match version {
                    reqwest::Version::HTTP_2 => "HTTP/2".to_string(),
                    reqwest::Version::HTTP_3 => "HTTP/3".to_string(),
                    _ => "HTTP/1.1".to_string(),
                };

                let (http3_advertised, http3_port) = if let Some(alt_svc) = headers.get("alt-svc") {
                    let val = alt_svc.to_str().unwrap_or("");
                    parse_alt_svc(val)
                } else {
                    (false, None)
                };

                let _content_length = headers
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse().ok())
                    .map(|v: u64| v);

                let body_started = Instant::now();
                let body = match resp.text().await {
                    Ok(text) => text,
                    Err(e) => {
                        last_error = Some(format!("failed to read body: {}", e));
                        if attempt < config.retries - 1 {
                            continue;
                        }
                        return (None, last_error);
                    }
                };
                let body_time_ms = body_started.elapsed().as_millis();
                let response_time_ms = network_time_ms + body_time_ms;

                let (
                    technologies,
                    mut security_findings,
                    probes,
                    trace_enabled,
                    api_docs,
                    websocket,
                    graphql,
                    cloud_info,
                    tls_info,
                ) = tokio::join!(
                    async {
                        let mut tech =
                            detect_from_headers_and_body(&config.signatures, &headers, &body);
                        run_optional_path_probes(client, &final_url, &config.signatures, &mut tech)
                            .await;
                        tech
                    },
                    async { analyze_security_headers(&headers) },
                    run_common_exposed_file_checks(
                        client,
                        &final_url,
                        &config.user_agent,
                        config.fast
                    ),
                    check_trace_method(client, &final_url, &config.user_agent),
                    async {
                        if config.fast {
                            Vec::new()
                        } else {
                            tokio::time::timeout(
                                Duration::from_secs(3),
                                discover_api_docs(client, &final_url, &config.user_agent),
                            )
                            .await
                            .unwrap_or_default()
                        }
                    },
                    async {
                        if config.fast {
                            None
                        } else {
                            tokio::time::timeout(
                                Duration::from_secs(3),
                                check_websocket(client, &final_url, &config.user_agent),
                            )
                            .await
                            .unwrap_or(None)
                        }
                    },
                    async {
                        if config.fast {
                            None
                        } else {
                            tokio::time::timeout(
                                Duration::from_secs(3),
                                detect_graphql(client, &final_url, &config.user_agent),
                            )
                            .await
                            .unwrap_or(None)
                        }
                    },
                    async { detect_cloud_provider(&headers, None) },
                    async {
                        if scheme == "https" && !config.fast {
                            crate::tls_analysis::get_tls_info(domain).await
                        } else {
                            None
                        }
                    },
                );

                let waf = detect_waf(&headers, &body);

                let takeover = check_takeover(domain, status_code, &body).await;
                let content_type_header = headers.get("content-type").and_then(|v| v.to_str().ok());
                let content_type_mismatch = crate::security::detect_content_type_mismatch(
                    content_type_header,
                    body.as_bytes(),
                );
                let timing = Some(TimingStats::new(
                    request_started.elapsed(),
                    request_started.elapsed(),
                    Some(body.len() as u64),
                ));

                security_findings.extend(analyze_information_disclosure(&headers, &body, &probes));

                let favicon_hash = if config.fast {
                    None
                } else {
                    fetch_favicon_hash(client, &final_url, &config.user_agent).await
                };

                if trace_enabled {
                    security_findings.push(SecurityFinding {
                        id: "trace-method-enabled".to_string(),
                        category: "information_disclosure".to_string(),
                        severity: Severity::Low,
                        title: "HTTP TRACE method enabled".to_string(),
                        explanation:
                            "TRACE can be used in Cross-Site Tracing attacks to steal cookies."
                                .to_string(),
                        evidence: "TRACE method returned valid response".to_string(),
                    });
                }
                let cookies = extract_cookies(&headers);

                let (detailed_cookies, cookie_findings) = analyze_cookies(&headers);
                security_findings.extend(cookie_findings);

                let redirect_info = analyze_redirect(&headers, &target);

                let ssrf_info: Option<SsrfVectorInfo> = if config.fast {
                    None
                } else {
                    tokio::time::timeout(
                        Duration::from_secs(3),
                        check_ssrf_vectors(client, &final_url, &config.user_agent),
                    )
                    .await
                    .unwrap_or(None)
                };

                let method_enum = if config.aggressive {
                    crate::security::enumerate_http_methods(client, &final_url).await
                } else {
                    MethodEnumerationResult::default()
                };

                let rate_limit = crate::security::parse_rate_limit_headers(&headers);
                let (cache, cache_findings) =
                    crate::security::analyze_cache_headers(&final_url, &headers);
                security_findings.extend(cache_findings);

                return (
                    Some(ProtocolResult {
                        url: final_url,
                        status_code,
                        response_time_ms,
                        technologies,
                        security_findings,
                        waf: Some(waf),
                        favicon_hash,
                        trace_enabled,
                        cookies,
                        detailed_cookies,
                        redirect_info,
                        http_version: Some(http_version),
                        http3_advertised,
                        http3_port,
                        websocket,
                        graphql,
                        api_docs,
                        cloud_info,
                        ssrf_info,
                        allowed_http_methods: method_enum.allowed_methods,
                        dangerous_http_methods: method_enum.dangerous_methods,
                        rate_limit: Some(rate_limit),
                        cache: Some(cache),
                        tls_info,
                        takeover,
                        content_type_mismatch,
                        timing,
                    }),
                    None,
                );
            }
            Err(err) => {
                last_error = Some(err.to_string());
                if attempt < config.retries - 1 {
                    continue;
                }
            }
        }
    }
    (None, last_error)
}

async fn probe_domain(client: &reqwest::Client, domain: &str, config: &ProbeConfig) -> ProbeResult {
    let _ = resolve_dns_cached(domain).await;

    let ct_info = if config.ct_logs {
        check_ct_logs(client, domain).await
    } else {
        None
    };

    let ((http_result, http_err), (https_result, https_err)) = tokio::join!(
        probe_protocol(client, domain, "http", config),
        probe_protocol(client, domain, "https", config)
    );

    if let Some(https) = https_result {
        let https_url = https.url.clone();
        let https_waf = https.waf.clone();
        let https_favicon = https.favicon_hash.clone();
        let https_tech = https.technologies.clone();
        let https_findings = https.security_findings.clone();
        let https_trace = https.trace_enabled;
        let https_cookies = https.cookies.clone();
        let https_response_time = https.response_time_ms;
        let https_status = https.status_code;
        let https_cloud_info = https.cloud_info.clone();
        let https_ssrf_info = https.ssrf_info.clone();
        return map_probe_success_with_both(
            domain,
            "https",
            &https_url,
            https_status,
            https_response_time,
            https_tech,
            https_findings,
            https_waf,
            https_favicon,
            Some(https_trace),
            https_cookies,
            http_result,
            Some(https),
            ct_info,
            https_cloud_info,
            https_ssrf_info,
        );
    }

    if let Some(http) = http_result {
        let http_url = http.url.clone();
        let http_waf = http.waf.clone();
        let http_favicon = http.favicon_hash.clone();
        let http_tech = http.technologies.clone();
        let http_findings = http.security_findings.clone();
        let http_trace = http.trace_enabled;
        let http_cookies = http.cookies.clone();
        let http_response_time = http.response_time_ms;
        let http_status = http.status_code;
        let http_cloud_info = http.cloud_info.clone();
        let http_ssrf_info = http.ssrf_info.clone();
        return map_probe_success_with_both(
            domain,
            "http",
            &http_url,
            http_status,
            http_response_time,
            http_tech,
            http_findings,
            http_waf,
            http_favicon,
            Some(http_trace),
            http_cookies,
            Some(http),
            None,
            ct_info,
            http_cloud_info,
            http_ssrf_info,
        );
    }

    let error_msg = http_err.or(https_err);
    map_probe_failure(domain, error_msg)
}

#[allow(dead_code, clippy::too_many_arguments)]
pub fn map_probe_success(
    domain: &str,
    scheme: &str,
    final_url: &str,
    status_code: u16,
    response_time_ms: u128,
    technologies: Vec<TechnologyMatch>,
    security_findings: Vec<SecurityFinding>,
    waf: Option<WafInfo>,
    favicon_hash: Option<String>,
    trace_enabled: Option<bool>,
    cookies: Vec<String>,
) -> ProbeResult {
    map_probe_success_with_both(
        domain,
        scheme,
        final_url,
        status_code,
        response_time_ms,
        technologies,
        security_findings,
        waf,
        favicon_hash,
        trace_enabled,
        cookies,
        None,
        None,
        None,
        None,
        None,
    )
}

#[allow(dead_code, clippy::too_many_arguments)]
pub fn map_probe_success_with_both(
    domain: &str,
    scheme: &str,
    final_url: &str,
    status_code: u16,
    response_time_ms: u128,
    technologies: Vec<TechnologyMatch>,
    security_findings: Vec<SecurityFinding>,
    waf: Option<WafInfo>,
    favicon_hash: Option<String>,
    trace_enabled: Option<bool>,
    cookies: Vec<String>,
    http_result: Option<ProtocolResult>,
    https_result: Option<ProtocolResult>,
    ct_info: Option<CertificateTransparencyInfo>,
    cloud_info: Option<super::security::CloudInfo>,
    ssrf_info: Option<SsrfVectorInfo>,
) -> ProbeResult {
    let mut res = ProbeResult {
        domain: domain.to_string(),
        probe_timestamp: Utc::now(),
        alive: true,
        protocol: Some(scheme.to_string()),
        final_url: Some(final_url.to_string()),
        status_code: Some(status_code),
        response_time_ms: Some(response_time_ms),
        error: None,
        technologies,
        security_findings,
        waf,
        favicon_hash,
        trace_enabled,
        cookies,
        redirect_info: None,
        detailed_cookies: Vec::new(),
        http_result,
        https_result,
        ct_info,
        cloud_info,
        ssrf_info,
        takeover: None,
        content_type_mismatch: None,
        allowed_http_methods: Vec::new(),
        dangerous_http_methods: Vec::new(),
        rate_limit: None,
        cache: None,
        tls_info: None,
        timing: None,
    };

    let preferred = res.https_result.as_ref().or(res.http_result.as_ref());
    if let Some(p) = preferred {
        res.redirect_info = p.redirect_info.clone();
        res.detailed_cookies = p.detailed_cookies.clone();
        res.takeover = p.takeover.clone();
        res.content_type_mismatch = p.content_type_mismatch.clone();
        res.allowed_http_methods = p.allowed_http_methods.clone();
        res.dangerous_http_methods = p.dangerous_http_methods.clone();
        res.rate_limit = p.rate_limit.clone();
        res.cache = p.cache.clone();
        res.tls_info = p.tls_info.clone();
        res.timing = p.timing.clone();
    }

    res
}

pub fn map_probe_failure(domain: &str, error: Option<String>) -> ProbeResult {
    ProbeResult {
        domain: domain.to_string(),
        probe_timestamp: Utc::now(),
        alive: false,
        protocol: None,
        final_url: None,
        status_code: None,
        response_time_ms: None,
        error,
        technologies: Vec::new(),
        security_findings: Vec::new(),
        waf: None,
        favicon_hash: None,
        trace_enabled: None,
        cookies: Vec::new(),
        redirect_info: None,
        detailed_cookies: Vec::new(),
        http_result: None,
        https_result: None,
        ct_info: None,
        cloud_info: None,
        ssrf_info: None,
        takeover: None,
        content_type_mismatch: None,
        allowed_http_methods: Vec::new(),
        dangerous_http_methods: Vec::new(),
        rate_limit: None,
        cache: None,
        tls_info: None,
        timing: None,
    }
}

async fn run_common_exposed_file_checks(
    client: &reqwest::Client,
    final_url: &str,
    user_agent: &str,
    fast: bool,
) -> Vec<ExposedPathObservation> {
    let Some(base_url) = origin_from_url(final_url) else {
        return Vec::new();
    };

    let probes = if fast {
        vec![
            "/.env",
            "/.git/config",
            "/server-status",
            "/debug",
            "/actuator/env",
        ]
    } else {
        vec![
            "/.env",
            "/.git/config",
            "/.git/HEAD",
            "/.svn/entries",
            "/phpinfo.php",
            "/server-status",
            "/server-info",
            "/actuator/env",
            "/actuator/heapdump",
            "/actuator/health",
            "/debug",
            "/php.ini",
            "/web.config",
            "/.htaccess",
            "/.htpasswd",
            "/configuration.php",
            "/config.php",
            "/settings.php",
            "/wp-config.php",
            "/.env.bak",
            "/.env.old",
            "/database.yml",
            "/credentials.json",
            "/secrets.json",
            "/admin/config.yml",
            "/.aws/credentials",
            "/console",
            "/api/debug",
            "/trace",
            "/debug/pprof",
            "/swagger-ui.html",
            "/api-docs",
            "/graphiql",
        ]
    };

    let start = Instant::now();
    let checks = stream::iter(probes)
        .map(|path| {
            let client = client.clone();
            let base_url = base_url.clone();
            let user_agent = user_agent.to_string();
            async move {
                if start.elapsed().as_secs() >= 2 {
                    return None;
                }
                let target = format!("{}{}", base_url, path);
                if let Ok(resp) = client
                    .get(&target)
                    .header(USER_AGENT, &user_agent)
                    .timeout(Duration::from_secs(1))
                    .send()
                    .await
                {
                    let status = resp.status().as_u16();
                    if status >= 400 {
                        return None;
                    }
                    let body = match resp.text().await {
                        Ok(text) => text,
                        Err(_) => return None,
                    };
                    let snippet: String = body.chars().take(80).collect();
                    if looks_like_sensitive_disclosure(path, &snippet) {
                        return Some(ExposedPathObservation {
                            path: path.to_string(),
                            status_code: status,
                            body_snippet: snippet,
                        });
                    }
                }
                None
            }
        })
        .buffer_unordered(20)
        .filter_map(|r| async { r })
        .collect::<Vec<_>>()
        .await;

    checks
}

fn origin_from_url(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    let scheme = parsed.scheme();
    let host = parsed.host_str()?;
    let authority = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };
    Some(format!("{scheme}://{authority}"))
}

fn looks_like_sensitive_disclosure(path: &str, body_snippet: &str) -> bool {
    let lowered = body_snippet.to_ascii_lowercase();
    match path {
        "/.env" | "/.env.bak" | "/.env.old" => {
            lowered.contains("password")
                || lowered.contains("secret")
                || lowered.contains("db_")
                || lowered.contains("api_key")
                || lowered.contains("token")
        }
        "/.git/config" | "/.git/HEAD" => {
            lowered.contains("[core]")
                || lowered.contains("repositoryformatversion")
                || lowered.contains("github.com")
        }
        "/.svn/entries" => lowered.contains("svn") || lowered.contains("revision"),
        "/phpinfo.php" | "/php.ini" => {
            lowered.contains("php version")
                || lowered.contains("phpinfo")
                || lowered.contains("system inf")
        }
        "/server-status" | "/server-info" => {
            lowered.contains("server version")
                || lowered.contains("apache server status")
                || lowered.contains(" uptime ")
        }
        "/actuator/env" => {
            lowered.contains("propertysources")
                || lowered.contains("activeprofiles")
                || lowered.contains("property")
        }
        "/actuator/heapdump" | "/debug" => true,
        "/actuator/health" => lowered.contains("status") && lowered.contains("up"),
        "/debug/pprof" | "/api/debug" => lowered.contains("pprof") || lowered.contains("profile"),
        "/configuration.php" | "/config.php" | "/settings.php" | "/wp-config.php" => {
            lowered.contains("db_") || lowered.contains("password") || lowered.contains("define")
        }
        "/.htaccess" | "/.htpasswd" => lowered.contains("rewrite") || lowered.contains("auth"),
        "/web.config" => lowered.contains("configuration") || lowered.contains("system.web"),
        "/database.yml" | "/admin/config.yml" => {
            lowered.contains("database") || lowered.contains("password")
        }
        "/credentials.json" | "/secrets.json" => {
            lowered.contains("key") || lowered.contains("secret")
        }
        "/.aws/credentials" => lowered.contains("aws") || lowered.contains("secret"),
        "/console" | "/trace" => true,
        "/swagger-ui.html" | "/api-docs" => {
            lowered.contains("swagger") || lowered.contains("openapi")
        }
        "/graphiql" => lowered.contains("graphiql") || lowered.contains("graphql"),
        "/favicon.ico" => body_snippet.len() < 50 && !body_snippet.is_empty(),
        _ => false,
    }
}

async fn run_optional_path_probes(
    client: &reqwest::Client,
    base_url: &str,
    signatures: &LoadedSignatures,
    matches: &mut Vec<TechnologyMatch>,
) {
    let base = base_url.trim_end_matches('/');
    let probes: Vec<_> = signatures
        .signatures
        .iter()
        .flat_map(|sig| {
            sig.path_probes
                .iter()
                .map(|p| (sig.name.clone(), p.clone()))
        })
        .collect();

    let results: Vec<(String, String, u16)> = stream::iter(probes)
        .map(|(name, probe)| {
            let client = client.clone();
            let target = format!("{}/{}", base, probe.path);
            async move {
                if let Ok(resp) = client.get(&target).send().await {
                    let status = resp.status().as_u16();
                    let body = resp.text().await.unwrap_or_default().to_ascii_lowercase();
                    if path_probe_matches(&probe, status, &body) {
                        return Some((name, probe.path.clone(), status));
                    }
                }
                None
            }
        })
        .buffer_unordered(20)
        .filter_map(|r| async { r })
        .collect()
        .await;

    for (name, path, status) in results {
        if let Some(existing) = matches.iter_mut().find(|m| m.name == name) {
            existing
                .evidence
                .push(format!("path:{} status={}", path, status));
            existing.confidence = existing.confidence.saturating_add(20).min(100);
        } else {
            matches.push(TechnologyMatch {
                name,
                confidence: 20,
                evidence: vec![format!("path:{} status={}", path, status)],
                version: None,
                is_dev_mode: false,
            });
        }
    }
    *matches = rank_matches(std::mem::take(matches));
}

async fn fetch_favicon_hash(
    client: &reqwest::Client,
    base_url: &str,
    user_agent: &str,
) -> Option<String> {
    let favicon_url = format!("{}/favicon.ico", base_url.trim_end_matches('/'));
    if let Ok(resp) = client
        .get(&favicon_url)
        .header(USER_AGENT, user_agent)
        .send()
        .await
    {
        if resp.status().as_u16() == 200 {
            if let Ok(bytes) = resp.bytes().await {
                return Some(crate::technology::compute_favicon_hash(&bytes));
            }
        }
    }
    None
}

fn extract_cookies(headers: &reqwest::header::HeaderMap) -> Vec<String> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(|s| s.split(';').next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

#[derive(Deserialize)]
struct CrtShEntry {
    name_value: Option<String>,
}

pub async fn check_ct_logs(
    client: &reqwest::Client,
    domain: &str,
) -> Option<CertificateTransparencyInfo> {
    let url = format!("https://crt.sh/?q=%.{}&output=json", domain);

    let resp = client
        .get(&url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .ok()?;

    if !resp.status().is_success() {
        return None;
    }

    let entries: Vec<CrtShEntry> = serde_json::from_str(&resp.text().await.ok()?).ok()?;

    let mut subdomains = Vec::new();
    let mut seen = HashSet::new();

    for entry in entries {
        if let Some(name_value) = entry.name_value {
            for name in name_value.split('\n') {
                let name = name.trim();
                if name.ends_with(&format!(".{}", domain))
                    && !name.starts_with('*')
                    && !name.contains(' ')
                    && seen.insert(name.to_lowercase())
                {
                    subdomains.push(name.to_string());
                }
            }
        }
    }

    Some(CertificateTransparencyInfo {
        subdomains,
        checked_at: Utc::now().to_rfc3339(),
    })
}

pub async fn check_ssrf_vectors(
    client: &reqwest::Client,
    base_url: &str,
    user_agent: &str,
) -> Option<SsrfVectorInfo> {
    let ssrf_params = vec![
        "url", "uri", "path", "dest", "redirect", "link", "file", "download", "src", "source",
        "href", "domain", "callback", "return", "next", "data", "q", "amp", "ti", "to", "out",
        "view",
    ];

    let test_targets = vec![
        "http://169.254.169.254/",
        "http://metadata.google.internal/",
        "http://127.0.0.1/",
        "http://localhost/",
        "http://0.0.0.0/",
    ];

    let mut vulnerable_params = Vec::new();

    for param in ssrf_params {
        for target in &test_targets {
            let test_url = format!("{}?{}={}", base_url.trim_end_matches('/'), param, target);

            let resp = client
                .get(&test_url)
                .header(USER_AGENT, user_agent)
                .timeout(Duration::from_secs(3))
                .send()
                .await
                .ok()?;

            let headers = resp.headers().clone();
            let body = resp.text().await.unwrap_or_default().to_lowercase();

            if body.contains("ami-id")
                || body.contains("instance-id")
                || body.contains("metadata.google.internal")
                || body.contains("internal ip")
                || body.contains("ec2")
                || body.contains("aws access")
            {
                vulnerable_params.push(param.to_string());
                break;
            }

            if headers
                .get("server")
                .map(|s| s.to_str().unwrap_or("").contains("metadata"))
                .unwrap_or(false)
            {
                vulnerable_params.push(param.to_string());
                break;
            }
        }
    }

    if vulnerable_params.is_empty() {
        None
    } else {
        Some(SsrfVectorInfo {
            vulnerable_parameters: vulnerable_params,
            checked_at: Utc::now().to_rfc3339(),
        })
    }
}

pub async fn check_websocket(
    client: &reqwest::Client,
    base_url: &str,
    user_agent: &str,
) -> Option<WebSocketInfo> {
    let ws_paths = vec![
        "/ws",
        "/websocket",
        "/socket.io",
        "/cable",
        "/stream",
        "/live",
    ];

    for path in ws_paths {
        let target = format!("{}{}", base_url.trim_end_matches('/'), path);

        let resp = client
            .get(&target)
            .header(USER_AGENT, user_agent)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .send()
            .await
            .ok()?;

        if resp.status().as_u16() == 101 {
            return Some(WebSocketInfo {
                path: path.to_string(),
                status: 101,
            });
        }

        let headers = resp.headers();
        if headers
            .get("upgrade")
            .map(|v| {
                v.to_str()
                    .unwrap_or("")
                    .to_lowercase()
                    .contains("websocket")
            })
            .unwrap_or(false)
        {
            return Some(WebSocketInfo {
                path: path.to_string(),
                status: resp.status().as_u16(),
            });
        }
    }
    None
}

pub async fn discover_api_docs(
    client: &reqwest::Client,
    base_url: &str,
    user_agent: &str,
) -> Vec<ApiDocInfo> {
    let doc_paths = vec![
        "/swagger.json",
        "/swagger.yaml",
        "/swagger.yml",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/api/swagger.json",
        "/api/v1/swagger.json",
        "/api/v1/openapi.json",
        "/v2/api-docs",
        "/v3/api-docs",
        "/docs",
        "/api/docs",
        "/api/v1/docs",
        "/redoc",
        "/api-doc",
        "/.well-known/openapi",
    ];

    let mut docs = Vec::new();

    for path in doc_paths {
        let target = format!("{}{}", base_url.trim_end_matches('/'), path);

        let resp = match client
            .get(&target)
            .header(USER_AGENT, user_agent)
            .send()
            .await
        {
            Ok(r) => r,
            Err(_) => continue,
        };

        if resp.status().is_success() {
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();

            if content_type.contains("json")
                || content_type.contains("yaml")
                || content_type.contains("yml")
            {
                if let Ok(json) =
                    serde_json::from_str::<Value>(&resp.text().await.unwrap_or_default())
                {
                    let (doc_type, title, version) = parse_api_doc_info(&json);
                    let endpoint_count = count_endpoints(&json);

                    docs.push(ApiDocInfo {
                        path: path.to_string(),
                        doc_type,
                        title,
                        version,
                        endpoint_count,
                    });
                }
            }
        }
    }

    docs
}

fn parse_api_doc_info(json: &Value) -> (String, Option<String>, Option<String>) {
    let doc_type = if json.get("swagger").is_some() {
        "Swagger 2.0".to_string()
    } else if let Some(openapi) = json.get("openapi") {
        format!("OpenAPI {}", openapi)
    } else {
        "Unknown".to_string()
    };

    let title = json
        .get("info")
        .and_then(|i| i.get("title"))
        .and_then(|t| t.as_str())
        .map(String::from);

    let version = json
        .get("info")
        .and_then(|i| i.get("version"))
        .and_then(|v| v.as_str())
        .map(String::from);

    (doc_type, title, version)
}

fn count_endpoints(json: &Value) -> usize {
    json.get("paths")
        .and_then(|p| p.as_object())
        .map(|paths| paths.len())
        .unwrap_or(0)
}

const INTROSPECTION_QUERY: &str = r#"{"query":"{ __schema { queryType { name } mutationType { name } subscriptionType { name } } }"}"#;

pub async fn detect_graphql(
    client: &reqwest::Client,
    base_url: &str,
    user_agent: &str,
) -> Option<GraphQLInfo> {
    let graphql_paths = vec![
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/graphql/v1",
        "/query",
    ];

    for path in graphql_paths {
        let target = format!("{}{}", base_url.trim_end_matches('/'), path);

        let graphiql = check_graphiql(client, &target, user_agent).await;

        let resp = client
            .post(&target)
            .header(USER_AGENT, user_agent)
            .header("Content-Type", "application/json")
            .body(INTROSPECTION_QUERY)
            .send()
            .await
            .ok()?;

        if resp.status().is_success() {
            let body: Value = serde_json::from_str(&resp.text().await.unwrap_or_default()).ok()?;

            if let Some(data) = body.get("data") {
                let has_mutations = data
                    .get("__schema")
                    .and_then(|s| s.get("mutationType"))
                    .and_then(|m| m.get("name"))
                    .is_some();
                let has_subscriptions = data
                    .get("__schema")
                    .and_then(|s| s.get("subscriptionType"))
                    .and_then(|s| s.get("name"))
                    .is_some();

                return Some(GraphQLInfo {
                    endpoint: path.to_string(),
                    introspection_enabled: true,
                    has_mutations,
                    has_subscriptions,
                    graphiql_available: graphiql,
                });
            }
        }
    }
    None
}

async fn check_graphiql(client: &reqwest::Client, url: &str, user_agent: &str) -> bool {
    let resp = client
        .get(url)
        .header(USER_AGENT, user_agent)
        .send()
        .await
        .ok();

    if let Some(r) = resp {
        let body = r.text().await.unwrap_or_default().to_lowercase();
        return body.contains("graphiql")
            || body.contains("graphql playground")
            || body.contains("graphql IDE");
    }
    false
}

#[cfg(test)]
mod tests {
    use crate::probe::{map_probe_success, parse_alt_svc};
    use crate::security::WafInfo;

    #[test]
    fn maps_success_result_shape() {
        let result = super::map_probe_success(
            "example.com",
            "https",
            "https://example.com/login",
            200,
            42,
            Vec::new(),
            Vec::new(),
            Some(WafInfo {
                name: Some("Cloudflare".to_string()),
                blocked: false,
                evidence: "cf-ray".to_string(),
            }),
            Some("hash123".to_string()),
            Some(false),
            vec!["session_id".to_string()],
        );
        assert!(result.alive);
        assert_eq!(result.domain, "example.com");
        assert_eq!(result.protocol.as_deref(), Some("https"));
        assert_eq!(result.status_code, Some(200));
        assert_eq!(result.response_time_ms, Some(42));
        assert!(result.error.is_none());
        assert!(result.technologies.is_empty());
        assert!(result.security_findings.is_empty());
        assert!(result.waf.is_some());
        assert!(result.favicon_hash.is_some());
        assert_eq!(result.trace_enabled, Some(false));
        assert_eq!(result.cookies.len(), 1);
    }

    #[test]
    fn maps_failure_result_shape() {
        let result = super::map_probe_failure("example.com", Some("timeout".to_string()));
        assert!(!result.alive);
        assert_eq!(result.domain, "example.com");
        assert!(result.protocol.is_none());
        assert!(result.final_url.is_none());
        assert!(result.status_code.is_none());
        assert!(result.response_time_ms.is_none());
        assert_eq!(result.error.as_deref(), Some("timeout"));
        assert!(result.technologies.is_empty());
        assert!(result.security_findings.is_empty());
        assert!(result.waf.is_none());
        assert!(result.favicon_hash.is_none());
        assert_eq!(result.trace_enabled, None);
        assert!(result.cookies.is_empty());
    }

    #[test]
    fn map_probe_success_with_all_fields() {
        use super::{map_probe_success, WafInfo};
        use crate::technology::TechnologyMatch;

        let technologies = vec![
            TechnologyMatch {
                name: "nginx".to_string(),
                confidence: 80,
                evidence: vec!["header:server~nginx".to_string()],
                version: None,
                is_dev_mode: false,
            },
            TechnologyMatch {
                name: "php".to_string(),
                confidence: 60,
                evidence: vec!["body:<?php".to_string()],
                version: None,
                is_dev_mode: false,
            },
        ];
        let result = map_probe_success(
            "api.example.com",
            "https",
            "https://api.example.com/v1/status",
            200,
            55,
            technologies,
            vec![],
            Some(WafInfo {
                name: Some("Cloudflare".to_string()),
                blocked: false,
                evidence: "cf-ray".to_string(),
            }),
            Some("abc123hash".to_string()),
            Some(true),
            vec!["PHPSESSID=xyz".to_string()],
        );
        assert!(result.alive);
        assert_eq!(result.domain, "api.example.com");
        assert_eq!(result.protocol.as_deref(), Some("https"));
        assert_eq!(result.status_code, Some(200));
        assert_eq!(result.response_time_ms, Some(55));
        assert!(result.error.is_none());
        assert_eq!(result.technologies.len(), 2);
        assert_eq!(result.technologies[0].name, "nginx");
        assert!(result.waf.is_some());
        assert!(result.favicon_hash.is_some());
        assert_eq!(result.trace_enabled, Some(true));
        assert_eq!(result.cookies.len(), 1);
    }

    #[test]
    fn map_probe_success_minimal() {
        let result = map_probe_success(
            "minimal.example",
            "http",
            "http://minimal.example/",
            301,
            10,
            vec![],
            vec![],
            None,
            None,
            None,
            vec![],
        );
        assert!(result.alive);
        assert_eq!(result.domain, "minimal.example");
        assert_eq!(result.protocol.as_deref(), Some("http"));
        assert_eq!(result.status_code, Some(301));
        assert_eq!(result.response_time_ms, Some(10));
    }

    #[test]
    fn probe_config_from_config_validation() {
        let mut cfg = crate::config::AppConfig {
            input: std::path::PathBuf::from("t.txt"),
            output: crate::cli::OutputFormat::Terminal,
            output_file: None,
            db: std::path::PathBuf::from("test.db"),
            concurrency: 0,
            timeout_secs: 0,
            retries: 1,
            user_agent: "test".to_string(),
            insecure: false,
            ct_logs: false,
            monitor: false,
            interval: 60,
            webhook: None,
            cve_lookup: false,
            fast: false,
            aggressive: false,
        };

        let probe_cfg = super::ProbeConfig::from_config(&cfg).unwrap();
        assert_eq!(probe_cfg.concurrency, 1);
        assert_eq!(probe_cfg.timeout_secs, 1);

        cfg.concurrency = 999;
        cfg.timeout_secs = 999;
        let probe_cfg2 = super::ProbeConfig::from_config(&cfg).unwrap();
        assert_eq!(probe_cfg2.concurrency, 500);
        assert_eq!(probe_cfg2.timeout_secs, 300);
    }

    #[test]
    fn probe_result_serialization_roundtrip() {
        let result = super::map_probe_success(
            "test.com",
            "https",
            "https://test.com/",
            200,
            42,
            vec![],
            vec![],
            None,
            None,
            None,
            vec![],
        );
        let json = serde_json::to_string(&result).unwrap();
        let roundtrip: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(roundtrip.get("domain").is_some());
    }

    #[test]
    fn parse_alt_svc_with_port() {
        let (advertised, port) = parse_alt_svc(r#"h3=":443""#);
        assert!(advertised);
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parse_alt_svc_with_explicit_port() {
        let (advertised, port) = parse_alt_svc(r#"h3="tcp:8443""#);
        assert!(advertised);
        assert_eq!(port, Some(8443));
    }

    #[test]
    fn parse_alt_svc_multiple_entries() {
        let (advertised, port) = parse_alt_svc(r#"h2="tcp:443", h3=":443""#);
        assert!(advertised);
        assert_eq!(port, Some(443));
    }

    #[test]
    fn parse_alt_svc_no_h3() {
        let (advertised, port) = parse_alt_svc(r#"h2="tcp:443""#);
        assert!(!advertised);
        assert_eq!(port, None);
    }

    #[cfg(test)]
    mod integration_tests {
        use crate::probe::check_takeover;
        use crate::security::{
            analyze_cache_headers, analyze_cookies, analyze_redirect, detect_content_type_mismatch,
            parse_rate_limit_headers,
        };
        use crate::technology::detect_js_version;
        use reqwest::header::{HeaderMap, HeaderValue};

        #[test]
        fn test_cookie_analysis_with_mock_data() {
            let mut headers = HeaderMap::new();
            headers.append(
                "set-cookie",
                HeaderValue::from_static("session_id=abc123; HttpOnly; Secure; SameSite=Strict"),
            );

            let (cookies, _findings) = analyze_cookies(&headers);
            assert_eq!(cookies.len(), 1);
            assert_eq!(cookies[0].name, "session_id");
            assert!(cookies[0].http_only);
            assert!(cookies[0].secure);
            assert_eq!(cookies[0].same_site, Some("Strict".to_string()));
        }

        #[test]
        fn test_cookie_security_findings_session_without_httponly() {
            let mut headers = HeaderMap::new();
            headers.append(
                "set-cookie",
                HeaderValue::from_static("session=value123; Secure"),
            );

            let (_, findings) = analyze_cookies(&headers);
            assert!(findings
                .iter()
                .any(|f| f.id == "session-cookie-missing-httponly"));
        }

        #[test]
        fn test_cookie_security_findings_missing_samesite() {
            let mut headers = HeaderMap::new();
            headers.append(
                "set-cookie",
                HeaderValue::from_static("session=value123; HttpOnly; Secure"),
            );

            let (_, findings) = analyze_cookies(&headers);
            assert!(findings.iter().any(|f| f.id == "cookie-missing-samesite"));
        }

        #[test]
        fn test_redirect_analysis() {
            let mut headers = HeaderMap::new();
            headers.append(
                "location",
                HeaderValue::from_static("https://example.com/page2"),
            );

            let result = analyze_redirect(&headers, "http://example.com/page");
            assert!(result.is_some());
            let redirect = result.unwrap();
            assert!(!redirect.https_downgrade);
            assert!(!redirect.has_external_redirect);
        }

        #[test]
        fn test_redirect_analysis_https_downgrade() {
            let mut headers = HeaderMap::new();
            headers.append(
                "location",
                HeaderValue::from_static("http://www.example.com/page"),
            );

            let result = analyze_redirect(&headers, "https://example.com/page");
            assert!(result.is_some());
            assert!(result.unwrap().https_downgrade);
        }

        #[test]
        fn test_rate_limit_parsing() {
            let mut headers = HeaderMap::new();
            headers.insert("x-ratelimit-limit", HeaderValue::from_static("100"));
            headers.insert("x-ratelimit-remaining", HeaderValue::from_static("50"));
            headers.insert("x-ratelimit-reset", HeaderValue::from_static("1640000000"));
            headers.insert("retry-after", HeaderValue::from_static("30"));

            let rate_limit = parse_rate_limit_headers(&headers);
            assert!(rate_limit.detected);
            assert_eq!(rate_limit.limit, Some(100));
            assert_eq!(rate_limit.remaining, Some(50));
            assert_eq!(rate_limit.reset, Some(1640000000));
            assert_eq!(rate_limit.retry_after, Some(30));
        }

        #[test]
        fn test_rate_limit_parsing_alternate_headers() {
            let mut headers = HeaderMap::new();
            headers.insert("x-rate-limit-limit", HeaderValue::from_static("200"));
            headers.insert("x-rate-limit-remaining", HeaderValue::from_static("100"));

            let rate_limit = parse_rate_limit_headers(&headers);
            assert!(rate_limit.detected);
            assert_eq!(rate_limit.limit, Some(200));
            assert_eq!(rate_limit.remaining, Some(100));
        }

        #[test]
        fn test_cache_analysis_on_admin_url() {
            let mut headers = HeaderMap::new();
            headers.insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=3600"),
            );

            let (analysis, findings) = analyze_cache_headers("https://example.com/admin", &headers);
            assert!(analysis.cache_control.is_some());
            assert!(findings.iter().any(|f| f.id == "sensitive-endpoint-cached"));
        }

        #[test]
        fn test_cache_analysis_private_on_sensitive() {
            let mut headers = HeaderMap::new();
            headers.insert(
                "cache-control",
                HeaderValue::from_static("private, max-age=3600"),
            );

            let (_, findings) = analyze_cache_headers("https://example.com/login", &headers);
            assert!(!findings.iter().any(|f| f.id == "sensitive-endpoint-cached"));
        }

        #[test]
        fn test_cache_analysis_no_cache_headers() {
            let headers = HeaderMap::new();

            let (_, findings) = analyze_cache_headers("https://example.com/admin", &headers);
            assert!(findings
                .iter()
                .any(|f| f.id == "sensitive-endpoint-no-cache-control"));
        }

        #[test]
        fn test_content_type_mismatch_html() {
            let html_content = b"<!DOCTYPE html><html><body>test</body></html>";
            let result = detect_content_type_mismatch(Some("text/html"), html_content);
            assert!(result.is_none());
        }

        #[test]
        fn test_content_type_mismatch_not_html() {
            let json_content = b"{\"key\": \"value\"}";
            let result = detect_content_type_mismatch(Some("text/html"), json_content);
            assert!(result.is_some());
            let mismatch = result.unwrap();
            assert_eq!(mismatch.declared, "text/html");
            assert_eq!(mismatch.detected, "not HTML");
        }

        #[test]
        fn test_content_type_mismatch_js() {
            let js_content = b"const x = 1;";
            let result = detect_content_type_mismatch(Some("application/javascript"), js_content);
            assert!(result.is_some());
            let mismatch = result.unwrap();
            assert_eq!(mismatch.detected, "not JSON/JS");
        }

        #[test]
        fn test_content_type_mismatch_json_valid() {
            let json_content = b"{\"version\": \"1.0\"}";
            let result = detect_content_type_mismatch(Some("application/json"), json_content);
            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_takeover_detection_aws_s3() {
            let body = "The specified bucket does not exist";
            let result = check_takeover("test.s3.amazonaws.com", 404, body).await;
            assert!(result.is_some());
            let takeover = result.unwrap();
            assert_eq!(takeover.service, "AWS S3");
        }

        #[tokio::test]
        async fn test_takeover_detection_heroku() {
            let body = "There is no app configured at that hostname";
            let result = check_takeover("my-app.herokuapp.com", 404, body).await;
            assert!(result.is_some());
            let takeover = result.unwrap();
            assert_eq!(takeover.service, "Heroku");
        }

        #[tokio::test]
        async fn test_takeover_detection_github_pages() {
            let body = "404 - Page Not Found";
            let result = check_takeover("user.github.io", 404, body).await;
            assert!(result.is_some());
            let takeover = result.unwrap();
            assert_eq!(takeover.service, "GitHub Pages");
        }

        #[tokio::test]
        async fn test_takeover_detection_nosuchbucket() {
            let body = "<Code>NoSuchBucket</Code>";
            let result = check_takeover("bucket.s3.amazonaws.com", 404, body).await;
            assert!(result.is_some());
            assert_eq!(result.unwrap().service, "AWS S3");
        }

        #[tokio::test]
        async fn test_takeover_detection_no_takeover_on_200() {
            let body = "Welcome to my site";
            let result = check_takeover("example.com", 200, body).await;
            assert!(result.is_none());
        }

        #[tokio::test]
        async fn test_takeover_detection_bitbucket() {
            let body = "Repository not found";
            let result = check_takeover("repo.bitbucket.org", 404, body).await;
            assert!(result.is_some());
            assert_eq!(result.unwrap().service, "Bitbucket");
        }

        #[tokio::test]
        async fn test_takeover_detection_gitlab() {
            let body = "Project not found";
            let result = check_takeover("gitlab.com/project", 404, body).await;
            assert!(result.is_some());
            assert_eq!(result.unwrap().service, "GitLab");
        }

        #[tokio::test]
        async fn test_takeover_detection_vercel() {
            let body = "is not a registered domain";
            let result = check_takeover("my-site.vercel.app", 404, body).await;
            assert!(result.is_some());
            assert_eq!(result.unwrap().service, "Vercel");
        }

        #[tokio::test]
        async fn test_takeover_detection_netlify() {
            let body = "doesn't exist";
            let result = check_takeover("site.netlify.app", 404, body).await;
            assert!(result.is_some());
            assert_eq!(result.unwrap().service, "Netlify");
        }

        #[test]
        fn test_js_version_detection_react() {
            let body = r#"react@18.2.0"#;
            let versions = detect_js_version(body);
            assert!(!versions.is_empty());
            assert!(versions
                .iter()
                .any(|v| v.name == "React" && v.version == Some("18.2.0".to_string())));
        }

        #[test]
        fn test_js_version_detection_vue() {
            let body = r#"Vue.component("test", { version: "3.2.0" })"#;
            let versions = detect_js_version(body);
            assert!(!versions
                .iter()
                .any(|v| v.name == "Vue.js" && v.version.is_some()));
        }

        #[test]
        fn test_js_version_detection_angular() {
            let body = r#"ng-version="14.1.0""#;
            let versions = detect_js_version(body);
            assert!(versions
                .iter()
                .any(|v| v.name == "Angular" && v.version == Some("14.1.0".to_string())));
        }

        #[test]
        fn test_js_version_detection_nextjs() {
            let body = r#"next@13.4.0"#;
            let versions = detect_js_version(body);
            assert!(versions
                .iter()
                .any(|v| v.name == "Next.js" && v.version == Some("13.4.0".to_string())));
        }

        #[test]
        fn test_js_version_detection_source_maps() {
            let body = r#"//# sourceMappingURL=app.js.map"#;
            let versions = detect_js_version(body);
            assert!(versions.iter().any(|v| v.name == "Source Maps Exposed"));
        }

        #[test]
        fn test_js_version_detection_devtools() {
            let body = r#"__REACT_DEVTOOLS_GLOBAL_HOOK__"#;
            let versions = detect_js_version(body);
            assert!(versions
                .iter()
                .any(|v| v.name == "React DevTools" && v.is_dev_mode));
        }

        #[test]
        fn test_cookie_analysis_multiple_cookies() {
            let mut headers = HeaderMap::new();
            headers.append(
                "set-cookie",
                HeaderValue::from_static("session=abc; HttpOnly; Secure"),
            );
            headers.append(
                "set-cookie",
                HeaderValue::from_static("tracking=xyz; Secure"),
            );

            let (cookies, _) = analyze_cookies(&headers);
            assert_eq!(cookies.len(), 1);
        }

        #[test]
        fn test_redirect_external_detection() {
            let mut headers = HeaderMap::new();
            headers.append(
                "location",
                HeaderValue::from_static("https://external.com/page"),
            );

            let result = analyze_redirect(&headers, "http://example.com/page");
            assert!(result.is_some());
            assert!(result.unwrap().has_external_redirect);
        }

        #[test]
        fn test_rate_limit_no_headers() {
            let headers = HeaderMap::new();
            let rate_limit = parse_rate_limit_headers(&headers);
            assert!(!rate_limit.detected);
            assert_eq!(rate_limit.limit, None);
        }

        #[test]
        fn test_cache_analysis_non_sensitive_url() {
            let mut headers = HeaderMap::new();
            headers.insert(
                "cache-control",
                HeaderValue::from_static("public, max-age=3600"),
            );

            let (_, findings) = analyze_cache_headers("https://example.com/blog", &headers);
            assert!(findings.is_empty());
        }

        #[tokio::test]
        async fn test_takeover_case_insensitive() {
            let body = "THE SPECIFIED BUCKET DOES NOT EXIST";
            let result = check_takeover("bucket.s3.amazonaws.com", 404, body).await;
            assert!(result.is_some());
        }
    }
}
