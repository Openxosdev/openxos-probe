use chrono::Utc;
use reqwest::header::{HeaderMap, USER_AGENT};
use serde::Serialize;
use url::Url;

const HTTP_METHODS: &[&str] = &[
    "OPTIONS", "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT",
];

#[derive(Debug, Clone, Default)]
pub struct MethodEnumerationResult {
    pub allowed_methods: Vec<String>,
    pub dangerous_methods: Vec<String>,
    pub findings: Vec<SecurityFinding>,
}

pub async fn enumerate_http_methods(
    client: &reqwest::Client,
    url: &str,
) -> MethodEnumerationResult {
    let mut result = MethodEnumerationResult::default();

    for method in HTTP_METHODS {
        let request = client.request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), url);

        match request.send().await {
            Ok(resp) => {
                let status = resp.status().as_u16();
                if status != 405 {
                    result.allowed_methods.push(method.to_string());

                    match *method {
                        "PUT" | "DELETE" | "TRACE" => {
                            result.dangerous_methods.push(method.to_string());
                            result.findings.push(SecurityFinding {
                                id: format!("enabled-{}", method.to_lowercase()),
                                category: "http_method".to_string(),
                                severity: Severity::Medium,
                                title: format!("{} method is enabled", method),
                                explanation: format!(
                                    "The {} method is enabled which could allow unauthorized operations.",
                                    method
                                ),
                                evidence: format!("{} returned status {}", method, status),
                            });
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => {}
        }
    }

    result
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "name", content = "service")]
#[allow(dead_code)]
pub enum CloudProvider {
    AWS { service: String },
    GCP { service: String },
    Azure { service: String },
    Cloudflare,
    DigitalOcean,
    Linode,
    Heroku,
    Vercel,
    Netlify,
    Akamai,
    Fastly,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudInfo {
    pub provider: CloudProvider,
    pub service: Option<String>,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SecurityFinding {
    pub id: String,
    pub category: String,
    pub severity: Severity,
    pub title: String,
    pub explanation: String,
    pub evidence: String,
}

#[derive(Debug, Clone)]
pub struct ExposedPathObservation {
    pub path: String,
    pub status_code: u16,
    pub body_snippet: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct WafInfo {
    pub name: Option<String>,
    pub blocked: bool,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CookieInfo {
    pub name: String,
    pub value_length: usize,
    pub secure: bool,
    pub http_only: bool,
    pub same_site: Option<String>,
    pub path: String,
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RedirectInfo {
    pub total_redirects: usize,
    pub final_url: Option<String>,
    pub https_downgrade: bool,
    pub has_external_redirect: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RateLimitInfo {
    pub detected: bool,
    pub limit: Option<u32>,
    pub remaining: Option<u32>,
    pub reset: Option<i64>,
    pub retry_after: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CacheAnalysis {
    pub cache_control: Option<String>,
    pub expires: Option<String>,
    pub pragma: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContentTypeMismatch {
    pub declared: String,
    pub detected: String,
}

pub fn detect_cloud_provider(headers: &HeaderMap, _ip: Option<String>) -> Option<CloudInfo> {
    if headers.get("x-amz-cf-id").is_some() || headers.get("x-amzn-requestid").is_some() {
        return Some(CloudInfo {
            provider: CloudProvider::AWS {
                service: "CloudFront".to_string(),
            },
            service: Some("CloudFront".to_string()),
            region: None,
        });
    }

    if headers.get("x-goog-api-key").is_some() || headers.get("x-cloud-trace-context").is_some() {
        return Some(CloudInfo {
            provider: CloudProvider::GCP {
                service: "GFE".to_string(),
            },
            service: Some("GFE".to_string()),
            region: None,
        });
    }

    if headers.get("x-azure-ref").is_some() {
        return Some(CloudInfo {
            provider: CloudProvider::Azure {
                service: "Azure CDN".to_string(),
            },
            service: Some("Azure CDN".to_string()),
            region: None,
        });
    }

    if headers.get("x-vercel-id").is_some() {
        return Some(CloudInfo {
            provider: CloudProvider::Vercel,
            service: None,
            region: headers
                .get("x-vercel-deployment-url")
                .and_then(|v| v.to_str().ok())
                .map(String::from),
        });
    }

    if headers.get("x-nf-request-id").is_some() {
        return Some(CloudInfo {
            provider: CloudProvider::Netlify,
            service: None,
            region: None,
        });
    }

    if let Some(server) = headers.get("server") {
        let server_str = server.to_str().unwrap_or("").to_lowercase();
        if server_str.contains("dokku") || server_str.contains("digitalocean") {
            return Some(CloudInfo {
                provider: CloudProvider::DigitalOcean,
                service: None,
                region: None,
            });
        }
    }

    if let Some(server) = headers.get("server") {
        let server_str = server.to_str().unwrap_or("").to_lowercase();
        if server_str.contains("linode") {
            return Some(CloudInfo {
                provider: CloudProvider::Linode,
                service: None,
                region: None,
            });
        }
    }

    if headers.get("cf-ray").is_some() {
        let cf_country = headers.get("cf-ipcountry").and_then(|c| c.to_str().ok());
        return Some(CloudInfo {
            provider: CloudProvider::Cloudflare,
            service: Some("CDN/WAF".to_string()),
            region: cf_country.map(String::from),
        });
    }

    if headers.get("x-heroku-request-id").is_some() {
        return Some(CloudInfo {
            provider: CloudProvider::Heroku,
            service: Some("Dyno".to_string()),
            region: headers
                .get("x-heroku-region")
                .and_then(|r| r.to_str().ok())
                .map(String::from),
        });
    }

    if headers.get("x-akamai-request-id").is_some() {
        return Some(CloudInfo {
            provider: CloudProvider::Akamai,
            service: Some("CDN".to_string()),
            region: None,
        });
    }

    if headers.get("x-fastly-request-id").is_some() {
        return Some(CloudInfo {
            provider: CloudProvider::Fastly,
            service: Some("CDN".to_string()),
            region: None,
        });
    }

    None
}

pub fn analyze_cookies(headers: &HeaderMap) -> (Vec<CookieInfo>, Vec<SecurityFinding>) {
    let mut cookies = Vec::new();
    let mut findings = Vec::new();

    if let Some(set_cookie) = headers.get_all("set-cookie").iter().next() {
        let header_str = set_cookie.to_str().unwrap_or("");
        for cookie_str in header_str.split(',') {
            let parts: Vec<&str> = cookie_str.split(';').collect();
            if parts.is_empty() {
                continue;
            }

            let name_value: Vec<&str> = parts[0].splitn(2, '=').collect();
            if name_value.len() != 2 {
                continue;
            }

            let name = name_value[0].trim().to_string();
            let secure = parts
                .iter()
                .any(|p| p.trim().eq_ignore_ascii_case("Secure"));
            let http_only = parts
                .iter()
                .any(|p| p.trim().eq_ignore_ascii_case("HttpOnly"));
            let same_site = parts
                .iter()
                .find(|p| p.trim().to_lowercase().starts_with("samesite"))
                .map(|p| p.split('=').nth(1).unwrap_or("").trim().to_string());
            let same_site_for_check = same_site.clone();
            let path = parts
                .iter()
                .find(|p| p.trim().to_lowercase().starts_with("path"))
                .and_then(|p| p.split('=').nth(1))
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let expires = parts
                .iter()
                .find(|p| p.trim().to_lowercase().starts_with("expires"))
                .and_then(|p| p.split('=').nth(1))
                .map(|s| s.trim().to_string());

            cookies.push(CookieInfo {
                name: name.clone(),
                value_length: name_value[1].len(),
                secure,
                http_only,
                same_site,
                path,
                expires,
            });

            let is_session = name.to_lowercase().contains("session")
                || name.to_lowercase().contains("auth")
                || name.to_lowercase().contains("token")
                || name.to_lowercase().contains("jwt");

            if is_session && !http_only {
                findings.push(SecurityFinding {
                    id: "session-cookie-missing-httponly".to_string(),
                    category: "cookie_security".to_string(),
                    severity: Severity::High,
                    title: "Session cookie missing HttpOnly flag".to_string(),
                    explanation: "Session cookies without HttpOnly can be accessed by JavaScript, increasing XSS risk.".to_string(),
                    evidence: format!("Cookie '{}' is a session cookie but lacks HttpOnly", name),
                });
            }

            if same_site_for_check.is_none() {
                findings.push(SecurityFinding {
                    id: "cookie-missing-samesite".to_string(),
                    category: "cookie_security".to_string(),
                    severity: Severity::Low,
                    title: "Cookie missing SameSite attribute".to_string(),
                    explanation: "SameSite helps prevent CSRF attacks.".to_string(),
                    evidence: format!("Cookie '{}' lacks SameSite attribute", name),
                });
            }
        }
    }

    (cookies, findings)
}

pub fn detect_waf(headers: &HeaderMap, body: &str) -> WafInfo {
    let lowered_body = body.to_ascii_lowercase();
    let mut waf_name: Option<String> = None;
    let mut evidence = String::new();

    if headers.get("cf-ray").is_some() {
        waf_name = Some("Cloudflare".to_string());
        evidence = "cf-ray header present".to_string();
    } else if headers.get("x-sucuri-id").is_some() {
        waf_name = Some("Sucuri".to_string());
        evidence = "x-sucuri-id header present".to_string();
    } else if headers.get("akamai-x-cache").is_some()
        || headers.get("akamai-x-request-id").is_some()
    {
        waf_name = Some("Akamai".to_string());
        evidence = "akamai header present".to_string();
    } else if let Some(val) = header_value(headers, "x-cdn") {
        let lowered_val = val.to_lowercase();
        if lowered_val.contains("imperva") {
            waf_name = Some("Imperva".to_string());
            evidence = format!("x-cdn: {}", val);
        } else if lowered_val.contains("incapsula") {
            waf_name = Some("Incapsula".to_string());
            evidence = format!("x-cdn: {}", val);
        }
    } else if headers.get("x-iinfo").is_some() {
        waf_name = Some("Imperva".to_string());
        evidence = "x-iinfo header present".to_string();
    } else if let Some(val) = header_value(headers, "server") {
        let lowered_val = val.to_lowercase();
        if lowered_val.contains("awselb") || lowered_val.contains("awsalb") {
            waf_name = Some("AWS WAF".to_string());
            evidence = format!("server: {}", val);
        } else if lowered_val.contains("cloudfront") {
            waf_name = Some("CloudFront".to_string());
            evidence = format!("server: {}", val);
        }
    } else if lowered_body.contains("attention required | cloudflare")
        || lowered_body.contains("cloudflare")
        || (lowered_body.contains("checking your browser") && lowered_body.contains("ray id"))
    {
        waf_name = Some("Cloudflare".to_string());
        evidence = "cloudflare challenge page detected".to_string();
    } else if lowered_body.contains("incapsula")
        || (lowered_body.contains("captcha required") && lowered_body.contains("incapsula"))
    {
        waf_name = Some("Incapsula".to_string());
        evidence = "incapsula challenge detected".to_string();
    } else if lowered_body.contains("_incapsula_") {
        waf_name = Some("Incapsula".to_string());
        evidence = "incapsula script detected".to_string();
    } else if lowered_body.contains("sucuri") && lowered_body.contains("cloudproxy") {
        waf_name = Some("Sucuri".to_string());
        evidence = "sucuri cloudproxy detected".to_string();
    } else if lowered_body.contains("403 error") && lowered_body.contains("request id") {
        waf_name = Some("AWS WAF".to_string());
        evidence = "aws waf 403 response detected".to_string();
    }

    WafInfo {
        name: waf_name,
        blocked: false,
        evidence,
    }
}

pub fn analyze_redirect(headers: &HeaderMap, current_url: &str) -> Option<RedirectInfo> {
    let location = headers.get("location")?;
    let location_str = location.to_str().ok()?;

    let current_is_https = current_url.starts_with("https://");
    let new_is_http = location_str.starts_with("http://");

    Some(RedirectInfo {
        total_redirects: 1,
        final_url: Some(location_str.to_string()),
        https_downgrade: current_is_https && new_is_http,
        has_external_redirect: is_external_redirect(current_url, location_str),
    })
}

fn is_external_redirect(current: &str, target: &str) -> bool {
    if !target.starts_with("http") {
        return false;
    }
    if target.starts_with(current) {
        return false;
    }

    let current_host = Url::parse(current)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));
    let target_host = Url::parse(target)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));

    current_host != target_host
}

pub fn analyze_security_headers(headers: &HeaderMap) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();

    assess_header_presence(
        headers,
        "content-security-policy",
        Severity::Medium,
        "Missing Content-Security-Policy",
        "Without CSP, malicious scripts can execute more easily if an injection bug exists.",
        &mut findings,
    );
    assess_header_presence(
        headers,
        "strict-transport-security",
        Severity::Medium,
        "Missing HSTS",
        "Without HSTS, browsers may downgrade to HTTP and expose sessions to interception.",
        &mut findings,
    );
    assess_header_presence(
        headers,
        "x-frame-options",
        Severity::Medium,
        "Missing X-Frame-Options",
        "Missing anti-framing headers can allow clickjacking attacks in embedded contexts.",
        &mut findings,
    );
    assess_header_presence(
        headers,
        "x-content-type-options",
        Severity::Low,
        "Missing X-Content-Type-Options",
        "Browsers may MIME-sniff content, increasing the chance of content-type confusion.",
        &mut findings,
    );
    assess_header_presence(
        headers,
        "referrer-policy",
        Severity::Low,
        "Missing Referrer-Policy",
        "Sensitive URL data may be leaked through the Referer header to third parties.",
        &mut findings,
    );
    assess_header_presence(
        headers,
        "permissions-policy",
        Severity::Low,
        "Missing Permissions-Policy",
        "Browser features are not explicitly restricted, increasing client-side attack surface.",
        &mut findings,
    );

    if let Some(value) = header_value(headers, "x-frame-options") {
        let normalized = value.to_ascii_lowercase();
        if normalized != "deny" && normalized != "sameorigin" {
            findings.push(SecurityFinding {
                id: "x-frame-options-weak".to_string(),
                category: "security_headers".to_string(),
                severity: Severity::Low,
                title: "Weak X-Frame-Options value".to_string(),
                explanation: "Only DENY or SAMEORIGIN reliably prevent unauthorized framing."
                    .to_string(),
                evidence: format!("x-frame-options={value}"),
            });
        }
    }

    if let Some(value) = header_value(headers, "x-content-type-options") {
        if value.to_ascii_lowercase() != "nosniff" {
            findings.push(SecurityFinding {
                id: "x-content-type-options-weak".to_string(),
                category: "security_headers".to_string(),
                severity: Severity::Low,
                title: "Weak X-Content-Type-Options value".to_string(),
                explanation: "Set X-Content-Type-Options to nosniff to prevent MIME sniffing."
                    .to_string(),
                evidence: format!("x-content-type-options={value}"),
            });
        }
    }

    if let Some(value) = header_value(headers, "strict-transport-security") {
        let lowered = value.to_ascii_lowercase();
        let max_age = lowered
            .split(';')
            .find_map(|part| part.trim().strip_prefix("max-age="))
            .and_then(|raw| raw.parse::<u64>().ok())
            .unwrap_or(0);
        if max_age < 15_552_000 {
            findings.push(SecurityFinding {
                id: "hsts-short-max-age".to_string(),
                category: "security_headers".to_string(),
                severity: Severity::Low,
                title: "HSTS max-age is short".to_string(),
                explanation:
                    "A short HSTS duration can reduce HTTPS downgrade protection effectiveness."
                        .to_string(),
                evidence: format!("strict-transport-security={value}"),
            });
        }
    }

    if let Some(value) = header_value(headers, "access-control-allow-origin") {
        if value == "*" {
            findings.push(SecurityFinding {
                id: "cors-wildcard".to_string(),
                category: "security_headers".to_string(),
                severity: Severity::Medium,
                title: "CORS wildcard origin".to_string(),
                explanation: "Access-Control-Allow-Origin: * allows any website to make requests to this API."
                    .to_string(),
                evidence: format!("access-control-allow-origin={value}"),
            });
        }
    }

    if let Some(value) = header_value(headers, "access-control-allow-credentials") {
        if value.to_ascii_lowercase() == "true" {
            if let Some(origin) = header_value(headers, "access-control-allow-origin") {
                if origin == "*" {
                    findings.push(SecurityFinding {
                        id: "cors-credentials-wildcard".to_string(),
                        category: "security_headers".to_string(),
                        severity: Severity::High,
                        title: "CORS allows credentials with wildcard origin".to_string(),
                        explanation: "This combination is insecure and should not be used in production.".to_string(),
                        evidence: "access-control-allow-credentials=true with access-control-allow-origin=*".to_string(),
                    });
                }
            }
        }
    }

    if let Some(value) = header_value(headers, "server") {
        if contains_version_leak(&value) {
            findings.push(SecurityFinding {
                id: "server-version-leak".to_string(),
                category: "information_disclosure".to_string(),
                severity: Severity::Low,
                title: "Server version leakage".to_string(),
                explanation:
                    "Server version details can help attackers pick known vulnerabilities."
                        .to_string(),
                evidence: format!("server={value}"),
            });
        }
    }

    if let Some(value) = header_value(headers, "x-powered-by") {
        findings.push(SecurityFinding {
            id: "x-powered-by-disclosure".to_string(),
            category: "information_disclosure".to_string(),
            severity: Severity::Low,
            title: "X-Powered-By header exposed".to_string(),
            explanation: "Technology banners provide fingerprinting data for attackers."
                .to_string(),
            evidence: format!("x-powered-by={value}"),
        });
    }

    if let Some(value) = header_value(headers, "x-aspnet-version") {
        findings.push(SecurityFinding {
            id: "aspnet-version-leak".to_string(),
            category: "information_disclosure".to_string(),
            severity: Severity::Low,
            title: "ASP.NET version exposed".to_string(),
            explanation: "ASP.NET version details can help attackers target known vulnerabilities."
                .to_string(),
            evidence: format!("x-aspnet-version={value}"),
        });
    }

    if let Some(value) = header_value(headers, "x-generator") {
        findings.push(SecurityFinding {
            id: "x-generator-disclosure".to_string(),
            category: "information_disclosure".to_string(),
            severity: Severity::Low,
            title: "X-Generator header exposed".to_string(),
            explanation: "Technology framework details exposed for fingerprinting.".to_string(),
            evidence: format!("x-generator={value}"),
        });
    }

    findings
}

pub fn parse_rate_limit_headers(headers: &HeaderMap) -> RateLimitInfo {
    let mut info = RateLimitInfo::default();

    if let Some(v) = headers.get("x-ratelimit-limit") {
        if let Ok(s) = v.to_str() {
            info.limit = s.parse().ok();
            info.detected = true;
        }
    }

    if let Some(v) = headers.get("x-ratelimit-remaining") {
        if let Ok(s) = v.to_str() {
            info.remaining = s.parse().ok();
        }
    }

    if let Some(v) = headers.get("x-ratelimit-reset") {
        if let Ok(s) = v.to_str() {
            info.reset = s.parse().ok();
        }
    }

    if let Some(v) = headers.get("retry-after") {
        if let Ok(s) = v.to_str() {
            info.retry_after = s.parse().ok().or_else(|| {
                chrono::DateTime::parse_from_rfc2822(s)
                    .ok()
                    .map(|dt| (dt.timestamp() - Utc::now().timestamp()) as u32)
            });
        }
    }

    if let Some(v) = headers.get("x-rate-limit-remaining") {
        if let Ok(s) = v.to_str() {
            info.remaining = s.parse().ok();
            info.detected = true;
        }
    }
    if let Some(v) = headers.get("x-rate-limit-limit") {
        if let Ok(s) = v.to_str() {
            info.limit = s.parse().ok();
        }
    }

    info
}

pub fn analyze_cache_headers(
    url: &str,
    headers: &HeaderMap,
) -> (CacheAnalysis, Vec<SecurityFinding>) {
    let cache_control = headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let expires = headers
        .get("expires")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    let pragma = headers
        .get("pragma")
        .and_then(|v| v.to_str().ok())
        .map(String::from);

    let mut findings = Vec::new();

    let is_sensitive = url.contains("login")
        || url.contains("admin")
        || url.contains("auth")
        || url.contains("dashboard")
        || url.contains("profile")
        || url.contains("account");

    if is_sensitive {
        if let Some(cc) = &cache_control {
            if !cc.contains("no-store") && !cc.contains("no-cache") && !cc.contains("private") {
                findings.push(SecurityFinding {
                    id: "sensitive-endpoint-cached".to_string(),
                    category: "caching".to_string(),
                    severity: Severity::Medium,
                    title: "Sensitive endpoint allows caching".to_string(),
                    explanation: "Endpoints containing login, admin, auth should not be cached."
                        .to_string(),
                    evidence: format!("Cache-Control: {} on sensitive URL {}", cc, url),
                });
            }
        } else {
            findings.push(SecurityFinding {
                id: "sensitive-endpoint-no-cache-control".to_string(),
                category: "caching".to_string(),
                severity: Severity::Low,
                title: "Sensitive endpoint missing Cache-Control".to_string(),
                explanation: "Sensitive URLs should explicitly set cache control headers."
                    .to_string(),
                evidence: format!("No Cache-Control header on {}", url),
            });
        }
    }

    (
        CacheAnalysis {
            cache_control,
            expires,
            pragma,
        },
        findings,
    )
}

pub fn analyze_information_disclosure(
    _headers: &HeaderMap,
    body: &str,
    exposed_paths: &[ExposedPathObservation],
) -> Vec<SecurityFinding> {
    let mut findings = Vec::new();
    let lowered_body = body.to_ascii_lowercase();

    if looks_like_stack_trace(&lowered_body) {
        findings.push(SecurityFinding {
            id: "stack-trace-disclosure".to_string(),
            category: "information_disclosure".to_string(),
            severity: Severity::High,
            title: "Stack trace disclosed in response".to_string(),
            explanation:
                "Stack traces reveal internal code paths and frameworks, aiding targeted exploits."
                    .to_string(),
            evidence: "body contains stack trace markers".to_string(),
        });
    }

    if looks_like_debug_info(&lowered_body) {
        findings.push(SecurityFinding {
            id: "debug-mode-enabled".to_string(),
            category: "information_disclosure".to_string(),
            severity: Severity::High,
            title: "Debug mode appears enabled".to_string(),
            explanation: "Debug endpoints can expose detailed internal state and should be disabled in production.".to_string(),
            evidence: "debug markers found in response body".to_string(),
        });
    }

    for observation in exposed_paths {
        let lowered_snippet = observation.body_snippet.to_ascii_lowercase();
        let (severity, title) = if observation.path == "/.env" || observation.path == "/.git/config"
        {
            (Severity::High, "Sensitive file exposed")
        } else if observation.path == "/server-status" || observation.path == "/phpinfo.php" {
            (Severity::Medium, "Diagnostic endpoint exposed")
        } else if observation.path == "/actuator/env" {
            (Severity::High, "Spring Boot actuator exposed")
        } else if observation.path == "/debug" || observation.path == "/actuator/heapdump" {
            (Severity::High, "Debug/heap dump endpoint exposed")
        } else {
            (Severity::Medium, "Potentially exposed internal endpoint")
        };
        findings.push(SecurityFinding {
            id: format!("exposed-file-{}", sanitize_id(&observation.path)),
            category: "information_disclosure".to_string(),
            severity,
            title: title.to_string(),
            explanation:
                "Publicly accessible debug/config endpoints can leak internal deployment details."
                    .to_string(),
            evidence: format!(
                "path={} status={} snippet={}",
                observation.path, observation.status_code, lowered_snippet
            ),
        });
    }

    findings
}

pub async fn check_trace_method(
    client: &reqwest::Client,
    base_url: &str,
    user_agent: &str,
) -> bool {
    let target = format!("{}/", base_url.trim_end_matches('/'));
    if let Ok(resp) = client
        .request(reqwest::Method::TRACE, &target)
        .header(USER_AGENT, user_agent)
        .send()
        .await
    {
        if resp.status().as_u16() == 200 {
            let body = resp.text().await.unwrap_or_default();
            return body.contains("TRACE") || body.contains("Apache") || body.contains("Microsoft");
        }
    }
    false
}

#[allow(dead_code)]
pub fn detect_content_type_mismatch(
    content_type: Option<&str>,
    body: &[u8],
) -> Option<ContentTypeMismatch> {
    let declared = content_type?.to_lowercase();

    if declared.contains("text/html") && !is_likely_html(body) {
        return Some(ContentTypeMismatch {
            declared: declared.clone(),
            detected: "not HTML".to_string(),
        });
    }

    if declared.contains("javascript") || declared.contains("application/json") {
        if !is_likely_json(body) {
            return Some(ContentTypeMismatch {
                declared: declared.clone(),
                detected: "not JSON/JS".to_string(),
            });
        }
    }

    if declared.contains("image/") && !is_likely_image(body) {
        return Some(ContentTypeMismatch {
            declared: declared.clone(),
            detected: "not image".to_string(),
        });
    }

    None
}

#[allow(dead_code)]
fn is_likely_html(body: &[u8]) -> bool {
    if body.len() < 10 {
        return false;
    }
    let snippet = String::from_utf8_lossy(&body[..body.len().min(1000)]);
    snippet.contains("<!DOCTYPE")
        || snippet.contains("<html")
        || snippet.contains("<head>")
        || snippet.contains("<script")
}

#[allow(dead_code)]
fn is_likely_json(body: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(body).is_ok()
}

#[allow(dead_code)]
fn is_likely_image(body: &[u8]) -> bool {
    if body.len() < 4 {
        return false;
    }
    let magic = &body[..4];
    magic == b"\x89PNG" || magic.starts_with(&[0xFF, 0xD8]) || magic == b"GIF8"
}

fn assess_header_presence(
    headers: &HeaderMap,
    header_name: &str,
    severity: Severity,
    title: &str,
    explanation: &str,
    findings: &mut Vec<SecurityFinding>,
) {
    if header_value(headers, header_name).is_none() {
        findings.push(SecurityFinding {
            id: format!("missing-{header_name}"),
            category: "security_headers".to_string(),
            severity,
            title: title.to_string(),
            explanation: explanation.to_string(),
            evidence: format!("{header_name} not present"),
        });
    }
}

fn header_value(headers: &HeaderMap, header_name: &str) -> Option<String> {
    headers
        .get(header_name)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

fn looks_like_stack_trace(body: &str) -> bool {
    let markers = [
        "stack trace",
        "traceback (most recent call last)",
        "exception in thread",
        "at java.",
        "panic: ",
        "fatal error:",
        "undefined index:",
        "line ",
    ];
    markers
        .iter()
        .filter(|marker| body.contains(**marker))
        .count()
        >= 2
}

fn contains_version_leak(value: &str) -> bool {
    let value_lower = value.to_ascii_lowercase();
    value_lower.contains('/')
        && value_lower.chars().any(|c| c.is_ascii_digit())
        && !value_lower.starts_with("http")
}

fn sanitize_id(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
}

fn looks_like_debug_info(body: &str) -> bool {
    let markers = [
        "debug mode",
        "debug: true",
        "debug mode enabled",
        "application.properties",
        "system.properties",
        "env:",
        "environment:",
        "heapdump",
        "jvm heap",
        "memory usage",
        "thread dump",
        "profiling enabled",
    ];
    let count = markers
        .iter()
        .filter(|marker| body.contains(**marker))
        .count();
    count >= 2
}

#[cfg(test)]
mod tests {
    use super::{
        analyze_information_disclosure, analyze_security_headers, contains_version_leak,
        detect_cloud_provider, detect_waf, ExposedPathObservation, Severity,
    };
    use reqwest::header::{HeaderMap, HeaderValue};
    use std::collections::HashSet;

    #[test]
    fn classifies_missing_headers_with_severity() {
        let headers = HeaderMap::new();
        let findings = analyze_security_headers(&headers);
        assert!(findings
            .iter()
            .any(|f| f.id == "missing-content-security-policy" && f.severity == Severity::Medium));
        assert!(
            findings
                .iter()
                .any(|f| f.id == "missing-strict-transport-security"
                    && f.severity == Severity::Medium)
        );
        assert!(findings
            .iter()
            .any(|f| f.id == "missing-referrer-policy" && f.severity == Severity::Low));
    }

    #[test]
    fn finds_disclosure_and_exposed_file_risks() {
        let headers = HeaderMap::new();
        let findings = analyze_information_disclosure(
            &headers,
            "Fatal error: panic: crashed\nStack trace here",
            &[ExposedPathObservation {
                path: "/.env".to_string(),
                status_code: 200,
                body_snippet: "DB_PASSWORD=secret".to_string(),
            }],
        );
        assert!(findings
            .iter()
            .any(|f| f.id == "stack-trace-disclosure" && f.severity == Severity::High));
        assert!(findings
            .iter()
            .any(|f| f.id.starts_with("exposed-file-") && f.severity == Severity::High));
    }

    #[test]
    fn version_leak_detection() {
        assert!(contains_version_leak("Apache/2.4.54"));
        assert!(contains_version_leak("nginx/1.24.0"));
        assert!(!contains_version_leak("example.com:8080"));
        assert!(!contains_version_leak("https://example.com"));
    }

    #[test]
    fn waf_detection_cloudflare() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-ray", HeaderValue::from_static("abc123"));
        let waf = detect_waf(&headers, "");
        assert_eq!(waf.name, Some("Cloudflare".to_string()));
    }

    #[test]
    fn waf_detection_akamai() {
        let mut headers = HeaderMap::new();
        headers.insert("akamai-x-cache", HeaderValue::from_static("hit"));
        let waf = detect_waf(&headers, "");
        assert_eq!(waf.name, Some("Akamai".to_string()));
    }

    #[test]
    fn waf_detection_sucuri() {
        let mut headers = HeaderMap::new();
        headers.insert("x-sucuri-id", HeaderValue::from_static("abc123"));
        let waf = detect_waf(&headers, "");
        assert_eq!(waf.name, Some("Sucuri".to_string()));
    }

    #[test]
    fn no_duplicate_findings_for_server_header() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx/1.24.0"));
        headers.insert("x-powered-by", HeaderValue::from_static("Express"));

        let security_findings = analyze_security_headers(&headers);
        let disclosure_findings = analyze_information_disclosure(&headers, "", &[]);

        let server_leak_count = security_findings
            .iter()
            .filter(|f| f.id == "server-version-leak")
            .count();
        let powered_by_count = disclosure_findings
            .iter()
            .filter(|f| f.id == "x-powered-by-disclosure")
            .count();

        assert_eq!(
            server_leak_count, 1,
            "server-version-leak should appear exactly once"
        );
        assert_eq!(
            powered_by_count, 0,
            "x-powered-by-disclosure should not appear in analyze_information_disclosure"
        );
    }

    #[test]
    fn analyze_security_headers_no_duplicates() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx/1.24.0"));
        headers.insert("x-powered-by", HeaderValue::from_static("PHP/8.1"));
        headers.insert("x-aspnet-version", HeaderValue::from_static("4.0.30319"));
        headers.insert("x-generator", HeaderValue::from_static("Hugo 0.92"));

        let findings = analyze_security_headers(&headers);
        let ids: Vec<_> = findings.iter().map(|f| f.id.clone()).collect();
        let unique: HashSet<_> = ids.iter().collect();
        assert_eq!(
            ids.len(),
            unique.len(),
            "Security headers findings should not have duplicate IDs"
        );
    }

    #[test]
    fn detect_waf_imperva_from_multiple_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("x-iinfo", HeaderValue::from_static("abc123"));
        let waf = detect_waf(&headers, "");
        assert_eq!(waf.name, Some("Imperva".to_string()));
    }

    #[test]
    fn detect_waf_cloudfront_from_server() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("CloudFront"));
        let waf = detect_waf(&headers, "");
        assert_eq!(waf.name, Some("CloudFront".to_string()));
    }

    #[test]
    fn detect_waf_aws_waf_from_body() {
        let headers = reqwest::header::HeaderMap::new();
        let body = "403 ERROR\nThe request could not be satisfied\nRequest Id: abc-123";
        let waf = super::detect_waf(&headers, body);
        assert_eq!(waf.name, Some("AWS WAF".to_string()));
    }

    #[test]
    fn detect_waf_fallback_body_detection() {
        let headers = reqwest::header::HeaderMap::new();
        let body = "403 error\nrequest id: 12345";
        let waf = super::detect_waf(&headers, body);
        assert!(waf.name.is_some());
    }

    #[test]
    fn detect_waf_incapsula_from_body() {
        let headers = HeaderMap::new();
        let body = "Incapsula incident ID: 12345\n CAPTCHA required for this resource.";
        let waf = detect_waf(&headers, body);
        assert_eq!(waf.name, Some("Incapsula".to_string()));
    }

    #[test]
    fn detect_waf_priority_order() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-ray", HeaderValue::from_static("abc123"));
        headers.insert("x-sucuri-id", HeaderValue::from_static("x"));
        let waf = detect_waf(&headers, "");
        assert_eq!(
            waf.name,
            Some("Cloudflare".to_string()),
            "cf-ray should take priority over x-sucuri-id"
        );
    }

    #[test]
    fn looks_like_stack_trace_multiple_markers() {
        let body = "fatal error:\n  at java\n  at spring\nundefined index: 5";
        assert!(super::looks_like_stack_trace(&body.to_lowercase()));
    }

    #[test]
    fn looks_like_debug_info_multiple_markers() {
        let body = "debug mode: true\napplication.properties loaded\njvm heap usage: 80%";
        assert!(super::looks_like_debug_info(&body.to_lowercase()));
    }

    #[test]
    fn sanitize_id_removes_special_chars() {
        assert_eq!(super::sanitize_id("/.env"), "--env".to_string());
        assert_eq!(
            super::sanitize_id("/actuator/env"),
            "-actuator-env".to_string()
        );
        assert_eq!(
            super::sanitize_id("/wp-config.php"),
            "-wp-config-php".to_string()
        );
        assert_eq!(super::sanitize_id("simple"), "simple".to_string());
    }

    #[test]
    fn severity_as_str() {
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Medium.as_str(), "medium");
        assert_eq!(Severity::Low.as_str(), "low");
    }

    #[test]
    fn analyze_security_headers_handles_empty() {
        let headers = HeaderMap::new();
        let findings = analyze_security_headers(&headers);
        assert!(
            findings.len() >= 6,
            "Should report all missing security headers"
        );
    }

    #[test]
    fn hsts_max_age_check() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
        let findings = analyze_security_headers(&headers);
        assert!(!findings.iter().any(|f| f.id == "hsts-short-max-age"));
    }

    #[test]
    fn hsts_short_max_age_detected() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "strict-transport-security",
            HeaderValue::from_static("max-age=86400"),
        );
        let findings = analyze_security_headers(&headers);
        assert!(findings.iter().any(|f| f.id == "hsts-short-max-age"));
    }

    #[test]
    fn analyze_information_disclosure_empty_inputs() {
        let headers = HeaderMap::new();
        let findings = analyze_information_disclosure(&headers, "", &[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn expose_path_observation_high_severity() {
        let obs = ExposedPathObservation {
            path: "/.env".to_string(),
            status_code: 200,
            body_snippet: "DB_PASSWORD=secret".to_string(),
        };
        let findings = analyze_information_disclosure(&HeaderMap::new(), "", &[obs]);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn expose_path_observation_medium_severity() {
        let obs = ExposedPathObservation {
            path: "/server-status".to_string(),
            status_code: 200,
            body_snippet: "Server Status".to_string(),
        };
        let findings = analyze_information_disclosure(&HeaderMap::new(), "", &[obs]);
        assert_eq!(findings[0].severity, Severity::Medium);
    }

    #[test]
    fn expose_path_observation_actuator_env_high() {
        let obs = ExposedPathObservation {
            path: "/actuator/env".to_string(),
            status_code: 200,
            body_snippet: "active-profiles".to_string(),
        };
        let findings = analyze_information_disclosure(&HeaderMap::new(), "", &[obs]);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn expose_path_observation_debug_high() {
        let obs = ExposedPathObservation {
            path: "/debug".to_string(),
            status_code: 200,
            body_snippet: "heap dump available".to_string(),
        };
        let findings = analyze_information_disclosure(&HeaderMap::new(), "", &[obs]);
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn cloud_provider_aws_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-cf-id", HeaderValue::from_static("abc123"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        let info = info.unwrap();
        match info.provider {
            super::CloudProvider::AWS { service } => {
                assert_eq!(service, "CloudFront");
            }
            _ => panic!("Expected AWS provider"),
        }
    }

    #[test]
    fn cloud_provider_gcp_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("x-cloud-trace-context", HeaderValue::from_static("abc/123"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        let info = info.unwrap();
        match info.provider {
            super::CloudProvider::GCP { service } => {
                assert_eq!(service, "GFE");
            }
            _ => panic!("Expected GCP provider"),
        }
    }

    #[test]
    fn cloud_provider_azure_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("x-azure-ref", HeaderValue::from_static("ref123"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        let info = info.unwrap();
        match info.provider {
            super::CloudProvider::Azure { service } => {
                assert_eq!(service, "Azure CDN");
            }
            _ => panic!("Expected Azure provider"),
        }
    }

    #[test]
    fn cloud_provider_vercel_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("x-vercel-id", HeaderValue::from_static("abc"));
        headers.insert(
            "x-vercel-deployment-url",
            HeaderValue::from_static("my-app.vercel.app"),
        );
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        match info.unwrap().provider {
            super::CloudProvider::Vercel => {}
            _ => panic!("Expected Vercel provider"),
        }
    }

    #[test]
    fn cloud_provider_netlify_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("x-nf-request-id", HeaderValue::from_static("abc123"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        match info.unwrap().provider {
            super::CloudProvider::Netlify => {}
            _ => panic!("Expected Netlify provider"),
        }
    }

    #[test]
    fn cloud_provider_cloudflare_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("cf-ray", HeaderValue::from_static("abc123"));
        headers.insert("cf-ipcountry", HeaderValue::from_static("US"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        let info = info.unwrap();
        match info.provider {
            super::CloudProvider::Cloudflare => {
                assert_eq!(info.region, Some("US".to_string()));
            }
            _ => panic!("Expected Cloudflare provider"),
        }
    }

    #[test]
    fn cloud_provider_heroku_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("x-heroku-request-id", HeaderValue::from_static("abc123"));
        headers.insert("x-heroku-region", HeaderValue::from_static("us-east-1"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        let info = info.unwrap();
        match info.provider {
            super::CloudProvider::Heroku => {
                assert_eq!(info.region, Some("us-east-1".to_string()));
            }
            _ => panic!("Expected Heroku provider"),
        }
    }

    #[test]
    fn cloud_provider_digitalocean_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("nginx digitalocean"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        match info.unwrap().provider {
            super::CloudProvider::DigitalOcean => {}
            _ => panic!("Expected DigitalOcean provider"),
        }
    }

    #[test]
    fn cloud_provider_linode_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("server", HeaderValue::from_static("Linode"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        match info.unwrap().provider {
            super::CloudProvider::Linode => {}
            _ => panic!("Expected Linode provider"),
        }
    }

    #[test]
    fn cloud_provider_akamai_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("x-akamai-request-id", HeaderValue::from_static("abc123"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        match info.unwrap().provider {
            super::CloudProvider::Akamai => {}
            _ => panic!("Expected Akamai provider"),
        }
    }

    #[test]
    fn cloud_provider_fastly_detection() {
        let mut headers = HeaderMap::new();
        headers.insert("x-fastly-request-id", HeaderValue::from_static("abc123"));
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_some());
        match info.unwrap().provider {
            super::CloudProvider::Fastly => {}
            _ => panic!("Expected Fastly provider"),
        }
    }

    #[test]
    fn cloud_provider_no_match() {
        let headers = HeaderMap::new();
        let info = detect_cloud_provider(&headers, None);
        assert!(info.is_none());
    }
}
