# Openxos-probe v0.1.0 - Next Level Improvements

## Current Status ✅ COMPLETED

All features from this document have been implemented in v0.1.0:

### Implemented Features
- [x] TLS/SSL Deep Analysis - ✅ IMPLEMENTED
- [x] Cookie Security Analysis - ✅ IMPLEMENTED  
- [x] Subdomain Takeover Detection - ✅ IMPLEMENTED
- [x] Response Time Statistics - ✅ IMPLEMENTED
- [x] Redirect Chain Analysis - ✅ IMPLEMENTED
- [x] Rate Limit Intelligence - ✅ IMPLEMENTED
- [x] HTTP Method Enumeration - ✅ IMPLEMENTED
- [x] Caching Header Analysis - ✅ IMPLEMENTED
- [x] Content-Type Mismatch - ✅ IMPLEMENTED
- [x] JS Framework Version Detection - ✅ IMPLEMENTED

## Historical Document

This document tracks planned improvements for future versions (v0.2.0+).

You detect protocols but don't analyze certificate details or TLS configuration.

**What to add:**

```rust
use rustls::Certificate;
use x509_parser::prelude::*;

struct TlsAnalysis {
    protocol_version: String,        // TLS 1.2, TLS 1.3
    cipher_suite: String,             // TLS_AES_256_GCM_SHA384
    certificate_info: CertificateInfo,
    weak_cipher: bool,                // Detect weak ciphers
    certificate_transparency: bool,   // CT log verification
    ocsp_stapling: bool,              // OCSP stapling support
}

struct CertificateInfo {
    subject: String,
    issuer: String,
    valid_from: DateTime<Utc>,
    valid_to: DateTime<Utc>,
    san: Vec<String>,                 // Subject Alternative Names
    days_until_expiry: i64,
    signature_algorithm: String,
    key_size: usize,
    is_self_signed: bool,
    is_wildcard: bool,
}

async fn analyze_tls_config(domain: &str) -> Result<TlsAnalysis> {
    // Get certificate chain from connection
    let connector = TlsConnector::new()?;
    let stream = TcpStream::connect(format!("{}:443", domain)).await?;
    let tls_stream = connector.connect(domain, stream).await?;
    
    // Extract peer certificates
    let certs = tls_stream.peer_certificates()?;
    
    // Parse first certificate (leaf cert)
    let (_, cert) = X509Certificate::from_der(&certs[0].0)?;
    
    let san = cert.subject_alternative_name()?
        .map(|san| san.value.general_names.iter()
            .filter_map(|name| match name {
                GeneralName::DNSName(dns) => Some(dns.to_string()),
                _ => None,
            })
            .collect())
        .unwrap_or_default();
    
    Ok(TlsAnalysis {
        certificate_info: CertificateInfo {
            subject: cert.subject().to_string(),
            issuer: cert.issuer().to_string(),
            valid_from: cert.validity().not_before.to_datetime(),
            valid_to: cert.validity().not_after.to_datetime(),
            san,
            days_until_expiry: (cert.validity().not_after.to_datetime() - Utc::now()).num_days(),
            // ... more fields
        },
        // ... more analysis
    })
}
```

**Bug Bounty Value:** Expired/expiring certificates, weak ciphers, missing OCSP stapling = quick findings.

### 2. Response Time Statistics & Anomaly Detection

Track timing patterns to detect slow endpoints (potential DoS vectors or heavy computation).

```rust
struct TimingAnalysis {
    dns_time: Duration,
    tcp_connect_time: Duration,
    tls_handshake_time: Duration,
    ttfb: Duration,              // Time to first byte
    total_time: Duration,
    download_speed: f64,          // bytes/sec
}

struct ResponseTimeStats {
    mean: Duration,
    median: Duration,
    p95: Duration,
    p99: Duration,
    slowest_endpoints: Vec<(String, Duration)>,
}

impl ResponseTimeStats {
    fn detect_anomalies(&self, threshold_multiplier: f64) -> Vec<String> {
        // Flag endpoints >3x mean response time
        self.slowest_endpoints.iter()
            .filter(|(_, duration)| {
                duration.as_millis() as f64 > self.mean.as_millis() as f64 * threshold_multiplier
            })
            .map(|(endpoint, _)| endpoint.clone())
            .collect()
    }
}
```

**Bug Bounty Value:** Slow endpoints often indicate expensive operations = potential DoS vectors.

### 3. Redirect Chain Analysis

You follow redirects but don't analyze the chain for security issues.

```rust
struct RedirectChainAnalysis {
    chain: Vec<RedirectHop>,
    total_redirects: usize,
    has_http_to_https: bool,
    has_https_to_http: bool,      // DOWNGRADE - CRITICAL!
    has_external_redirect: bool,   // Open redirect potential
    has_circular_redirect: bool,
}

struct RedirectHop {
    from: String,
    to: String,
    status_code: u16,
    location_header: String,
}

fn analyze_redirect_chain(response: &Response) -> RedirectChainAnalysis {
    // Check for HTTP -> HTTPS downgrade (CRITICAL FINDING)
    // Check for open redirect patterns
    // Check for circular redirects
    // Check for cross-domain redirects
}
```

**Bug Bounty Value:** 
- HTTPS downgrade = HIGH severity
- Open redirect = MEDIUM severity
- Cross-domain redirect = potential SSRF

### 4. Cookie Security Analysis

Missing comprehensive cookie analysis.

```rust
struct CookieAnalysis {
    cookies: Vec<CookieInfo>,
    findings: Vec<CookieFinding>,
}

struct CookieInfo {
    name: String,
    value_length: usize,
    secure: bool,
    http_only: bool,
    same_site: Option<String>,
    domain: Option<String>,
    path: String,
    expires: Option<DateTime<Utc>>,
}

struct CookieFinding {
    severity: Severity,
    cookie_name: String,
    issue: String,
}

fn analyze_cookies(headers: &HeaderMap) -> CookieAnalysis {
    let mut findings = Vec::new();
    
    for cookie in parse_cookies(headers) {
        // Missing Secure flag on HTTPS
        if !cookie.secure && url.starts_with("https") {
            findings.push(CookieFinding {
                severity: Severity::Medium,
                cookie_name: cookie.name.clone(),
                issue: "Missing Secure flag on HTTPS cookie".to_string(),
            });
        }
        
        // Missing HttpOnly on session cookies
        if cookie.name.to_lowercase().contains("session") && !cookie.http_only {
            findings.push(CookieFinding {
                severity: Severity::High,
                cookie_name: cookie.name.clone(),
                issue: "Session cookie missing HttpOnly flag (XSS risk)".to_string(),
            });
        }
        
        // Missing SameSite
        if cookie.same_site.is_none() {
            findings.push(CookieFinding {
                severity: Severity::Low,
                cookie_name: cookie.name.clone(),
                issue: "Missing SameSite attribute (CSRF risk)".to_string(),
            });
        }
    }
    
    CookieAnalysis { cookies: parsed_cookies, findings }
}
```

**Bug Bounty Value:** Cookie security issues are common and reportable.

### 5. Rate Limit Intelligence

You detect rate limits but don't extract quotas or test boundaries.

```rust
struct RateLimitIntelligence {
    detected: bool,
    limit: Option<u32>,
    remaining: Option<u32>,
    reset_timestamp: Option<DateTime<Utc>>,
    window_seconds: Option<u32>,
    limit_per_hour: Option<u32>,
    bypass_headers: Vec<String>,     // X-Forwarded-For, etc.
}

async fn probe_rate_limits(client: &Client, url: &str) -> RateLimitIntelligence {
    let mut info = RateLimitIntelligence::default();
    
    // Send initial request
    let resp = client.get(url).send().await?;
    
    // Parse standard headers
    if let Some(limit) = resp.headers().get("x-ratelimit-limit") {
        info.limit = limit.to_str()?.parse().ok();
    }
    
    if let Some(remaining) = resp.headers().get("x-ratelimit-remaining") {
        info.remaining = remaining.to_str()?.parse().ok();
    }
    
    if let Some(reset) = resp.headers().get("x-ratelimit-reset") {
        let timestamp: i64 = reset.to_str()?.parse()?;
        info.reset_timestamp = Some(DateTime::from_timestamp(timestamp, 0)?);
    }
    
    // Test bypass headers (optional aggressive mode)
    if aggressive_mode {
        let bypass_headers = vec![
            "X-Forwarded-For",
            "X-Originating-IP",
            "X-Remote-IP",
            "X-Client-IP",
        ];
        
        for header in bypass_headers {
            let resp = client.get(url)
                .header(header, "127.0.0.1")
                .send()
                .await?;
            
            if !is_rate_limited(&resp) {
                info.bypass_headers.push(header.to_string());
            }
        }
    }
    
    info
}
```

**Bug Bounty Value:** Rate limit bypass = valid finding.

### 6. JavaScript Framework Detection

You detect React/Vue/Angular but not versions or build info.

```rust
const JS_FRAMEWORK_PATTERNS: &[(&str, &str)] = &[
    // React
    (r"react@(\d+\.\d+\.\d+)", "React"),
    (r"__REACT_DEVTOOLS_GLOBAL_HOOK__", "React (Dev Mode)"),
    
    // Vue
    (r"Vue\.version\s*=\s*['\"](\d+\.\d+\.\d+)", "Vue.js"),
    
    // Angular
    (r"ng-version=['\"](\d+\.\d+\.\d+)", "Angular"),
    
    // Next.js
    (r"__NEXT_DATA__", "Next.js"),
    (r"/_next/static/chunks/", "Next.js"),
    
    // Nuxt
    (r"__NUXT__", "Nuxt.js"),
    
    // Svelte
    (r"__SVELTE__", "Svelte"),
];

async fn detect_js_frameworks(url: &str, body: &str) -> Vec<JsFramework> {
    let mut frameworks = Vec::new();
    
    for (pattern, name) in JS_FRAMEWORK_PATTERNS {
        let regex = Regex::new(pattern).unwrap();
        if let Some(captures) = regex.captures(body) {
            frameworks.push(JsFramework {
                name: name.to_string(),
                version: captures.get(1).map(|m| m.as_str().to_string()),
                dev_mode: name.contains("Dev Mode"),
            });
        }
    }
    
    // Check webpack bundle for source maps
    if body.contains("//# sourceMappingURL=") {
        frameworks.push(JsFramework {
            name: "Webpack (Source Maps Exposed)".to_string(),
            version: None,
            dev_mode: true,
        });
    }
    
    frameworks
}
```

**Bug Bounty Value:** Dev mode detection, exposed source maps = information disclosure.

### 7. Server-Side Template Injection (SSTI) Detection

Basic probe for template engines.

```rust
struct SstiProbe {
    template_engine: Option<String>,
    potential_ssti: bool,
    test_payload: String,
    response_pattern: String,
}

async fn probe_ssti(client: &Client, url: &str) -> Option<SstiProbe> {
    // Test basic math expression
    let payloads = vec![
        ("{{7*7}}", "49"),           // Jinja2, Twig
        ("${7*7}", "49"),            // Freemarker, Velocity
        ("<%= 7*7 %>", "49"),        // ERB
        ("#{7*7}", "49"),            // Ruby
    ];
    
    for (payload, expected) in payloads {
        let test_url = format!("{}?test={}", url, payload);
        
        if let Ok(resp) = client.get(&test_url).send().await {
            let body = resp.text().await.unwrap_or_default();
            
            if body.contains(expected) {
                return Some(SstiProbe {
                    template_engine: Some(detect_engine_from_payload(payload)),
                    potential_ssti: true,
                    test_payload: payload.to_string(),
                    response_pattern: expected.to_string(),
                });
            }
        }
    }
    
    None
}
```

**IMPORTANT:** This is aggressive testing. Only run with explicit permission. Add `--aggressive` flag requirement.

### 8. Subdomain Takeover Detection

Check if discovered subdomains are vulnerable to takeover.

```rust
const TAKEOVER_FINGERPRINTS: &[(&str, &str)] = &[
    ("There is no app configured at that hostname", "Heroku"),
    ("No such app", "Heroku"),
    ("404 - Page Not Found", "GitHub Pages"),
    ("The specified bucket does not exist", "AWS S3"),
    ("NoSuchBucket", "AWS S3"),
    ("Repository not found", "Bitbucket"),
    ("Project not found", "GitLab"),
];

async fn check_subdomain_takeover(domain: &str, response_body: &str) -> Option<TakeoverVulnerability> {
    for (pattern, service) in TAKEOVER_FINGERPRINTS {
        if response_body.contains(pattern) {
            return Some(TakeoverVulnerability {
                domain: domain.to_string(),
                service: service.to_string(),
                fingerprint: pattern.to_string(),
                severity: Severity::High,
            });
        }
    }
    
    None
}
```

**Bug Bounty Value:** Subdomain takeover = CRITICAL/HIGH severity finding.

### 9. Content-Type Mismatch Detection

Detect when Content-Type header doesn't match actual content.

```rust
fn detect_content_type_mismatch(headers: &HeaderMap, body: &[u8]) -> Option<ContentTypeMismatch> {
    let declared_type = headers.get("content-type")
        .and_then(|v| v.to_str().ok())?;
    
    let actual_type = infer::get(body)?;
    
    // Check for mismatch
    if declared_type.contains("text/html") && actual_type.mime_type().contains("image") {
        return Some(ContentTypeMismatch {
            declared: declared_type.to_string(),
            actual: actual_type.mime_type().to_string(),
            risk: "Potential file upload bypass or MIME confusion attack".to_string(),
        });
    }
    
    None
}
```

**Bug Bounty Value:** Content-Type confusion can lead to XSS or file upload bypasses.

### 10. Backup File Detection (Enhanced)

You check 27 exposed files but can add pattern-based detection.

```rust
async fn detect_backup_files(base_url: &str, client: &Client) -> Vec<BackupFile> {
    let mut found = Vec::new();
    
    // Extract base filename from URL
    let path_segments: Vec<&str> = base_url.split('/').collect();
    if let Some(filename) = path_segments.last() {
        // Generate backup patterns
        let patterns = vec![
            format!("{}.bak", filename),
            format!("{}.old", filename),
            format!("{}.backup", filename),
            format!("{}~", filename),
            format!("{}.orig", filename),
            format!("{}.save", filename),
            format!("copy of {}", filename),
            format!("{}.1", filename),
            format!("{}.2", filename),
        ];
        
        for pattern in patterns {
            let backup_url = base_url.replace(filename, &pattern);
            
            if let Ok(resp) = client.get(&backup_url).send().await {
                if resp.status().is_success() {
                    found.push(BackupFile {
                        url: backup_url,
                        pattern: pattern.clone(),
                    });
                }
            }
        }
    }
    
    found
}
```

### 11. HTTP Method Enumeration

Test all HTTP methods for misconfigurations.

```rust
const HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "DELETE", "PATCH", 
    "OPTIONS", "HEAD", "TRACE", "CONNECT",
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"
];

struct MethodEnumeration {
    allowed_methods: Vec<String>,
    dangerous_methods: Vec<String>,
    findings: Vec<MethodFinding>,
}

async fn enumerate_http_methods(url: &str, client: &Client) -> MethodEnumeration {
    let mut allowed = Vec::new();
    let mut dangerous = Vec::new();
    let mut findings = Vec::new();
    
    for method in HTTP_METHODS {
        let request = client.request(
            Method::from_bytes(method.as_bytes()).unwrap(),
            url
        );
        
        if let Ok(resp) = request.send().await {
            if resp.status() != StatusCode::METHOD_NOT_ALLOWED {
                allowed.push(method.to_string());
                
                // Flag dangerous methods
                if matches!(*method, "PUT" | "DELETE" | "TRACE" | "CONNECT") {
                    dangerous.push(method.to_string());
                    findings.push(MethodFinding {
                        method: method.to_string(),
                        severity: Severity::Medium,
                        description: format!("{} method enabled", method),
                    });
                }
            }
        }
    }
    
    MethodEnumeration { allowed_methods: allowed, dangerous_methods: dangerous, findings }
}
```

**Bug Bounty Value:** Enabled PUT/DELETE methods = potential unauthorized file upload/deletion.

### 12. Caching Header Analysis

Detect sensitive data caching issues.

```rust
struct CacheAnalysis {
    cache_control: Option<String>,
    expires: Option<String>,
    pragma: Option<String>,
    findings: Vec<CacheFinding>,
}

fn analyze_cache_headers(url: &str, headers: &HeaderMap) -> CacheAnalysis {
    let mut findings = Vec::new();
    
    let cache_control = headers.get("cache-control")
        .and_then(|v| v.to_str().ok())
        .map(String::from);
    
    // Check if sensitive endpoints are cached
    let is_sensitive = url.contains("login") || 
                       url.contains("admin") || 
                       url.contains("api") ||
                       url.contains("auth");
    
    if is_sensitive {
        if let Some(cc) = &cache_control {
            if !cc.contains("no-store") && !cc.contains("no-cache") {
                findings.push(CacheFinding {
                    severity: Severity::Medium,
                    issue: "Sensitive endpoint allows caching".to_string(),
                    recommendation: "Add Cache-Control: no-store, no-cache".to_string(),
                });
            }
        } else {
            findings.push(CacheFinding {
                severity: Severity::Medium,
                issue: "Sensitive endpoint missing Cache-Control header".to_string(),
                recommendation: "Add Cache-Control: no-store, no-cache, must-revalidate".to_string(),
            });
        }
    }
    
    CacheAnalysis {
        cache_control,
        expires: headers.get("expires").and_then(|v| v.to_str().ok()).map(String::from),
        pragma: headers.get("pragma").and_then(|v| v.to_str().ok()).map(String::from),
        findings,
    }
}
```

## Performance Improvements

### 13. Smart Request Batching

Batch similar requests to same host.

```rust
struct RequestBatcher {
    batches: HashMap<String, Vec<Request>>,
}

impl RequestBatcher {
    async fn execute_batches(&self, client: &Client) -> Vec<Response> {
        let mut all_responses = Vec::new();
        
        for (host, requests) in &self.batches {
            // Execute all requests to same host in parallel
            let futures: Vec<_> = requests.iter()
                .map(|req| client.execute(req.clone()))
                .collect();
            
            let responses = join_all(futures).await;
            all_responses.extend(responses.into_iter().filter_map(Result::ok));
        }
        
        all_responses
    }
}
```

### 14. Intelligent Retry with Exponential Backoff

```rust
async fn request_with_retry(
    client: &Client,
    url: &str,
    max_retries: u32
) -> Result<Response> {
    let mut delay = Duration::from_millis(100);
    
    for attempt in 0..max_retries {
        match client.get(url).send().await {
            Ok(resp) => return Ok(resp),
            Err(e) if attempt < max_retries - 1 => {
                // Exponential backoff
                tokio::time::sleep(delay).await;
                delay *= 2;
            }
            Err(e) => return Err(e.into()),
        }
    }
    
    unreachable!()
}
```

### 15. Response Deduplication

Don't analyze identical responses multiple times.

```rust
use std::collections::HashMap;
use sha2::{Sha256, Digest};

struct ResponseCache {
    cache: HashMap<String, AnalysisResult>,
}

impl ResponseCache {
    fn hash_response(body: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(body);
        format!("{:x}", hasher.finalize())
    }
    
    async fn analyze_with_cache(&mut self, body: &[u8]) -> AnalysisResult {
        let hash = Self::hash_response(body);
        
        if let Some(cached) = self.cache.get(&hash) {
            return cached.clone();
        }
        
        let result = perform_analysis(body).await;
        self.cache.insert(hash, result.clone());
        result
    }
}
```

## CLI Improvements

### 16. Interactive Mode

```bash
openxos-probe --interactive

# Opens TUI interface with:
# - Live results display
# - Filtering options
# - Export selected results
# - Re-scan specific targets
```

### 17. Diff Mode

Compare two scan results to detect changes.

```bash
openxos-probe --diff old_scan.json new_scan.json

# Shows:
# - New technologies detected
# - Removed technologies
# - New security findings
# - Fixed security issues
# - Infrastructure changes
```

## Recommended Priority Order

**High Priority (Do These First):**
1. TLS/SSL Deep Analysis - High security value
2. Cookie Security Analysis - Common findings
3. Subdomain Takeover Detection - Critical findings
4. Response Time Stats - Performance insights
5. Redirect Chain Analysis - Security issues

**Medium Priority:**
6. Rate Limit Intelligence - Useful for API testing
7. HTTP Method Enumeration - Quick wins
8. Caching Header Analysis - Common misconfiguration
9. Content-Type Mismatch - Interesting edge cases
10. JavaScript Framework Detection Enhancement

**Low Priority (Nice to Have):**
11. SSTI Probing - Requires aggressive mode
12. Backup File Pattern Detection - Already have basic version
13. Request Batching - Optimization
14. Response Deduplication - Optimization
15. Interactive/Diff Mode - UX enhancement

## Conclusion

Your current implementation is already strong with 30+ features. The additions above will push it from "comprehensive" to "industry-leading."

**Realistic v0.1.0 scope:** Add items 1-5 from high priority list.

**Total additional development time:** 2-3 weeks for high-priority items.

**Performance note:** Don't compare to curl. Compare to other recon tools like httpx, httprobe, or aquatone. Your tool does 10x more analysis.
