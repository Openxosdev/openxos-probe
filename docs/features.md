# Feature Documentation (v0.1.0)

*Last updated: 2026-2027*

## Technology Fingerprinting

### Description
Detects web technologies based on HTTP headers, response bodies, and path probes. Uses signature-based matching with Aho-Corasick algorithm for efficient body scanning.

### Usage
Automatically enabled when probing domains. Technology signatures are loaded from the `signatures/` directory.

### Output Interpretation
```
Technologies: nginx(80), WordPress(70), PHP(60)
```

- Confidence scores (0-100) indicate match strength
- Higher scores = more reliable detection

---

## Security Header Analysis

### Description
Analyzes HTTP responses for missing or weak security headers including CSP, HSTS, X-Frame-Options, and CORS policies.

### Usage
Automatically enabled during scans.

### Output Interpretation
| Finding ID | Severity | Description |
|-----------|----------|-------------|
| missing-content-security-policy | medium | CSP header not set |
| missing-strict-transport-security | medium | HSTS not enabled |
| cors-wildcard | medium | CORS allows all origins |
| cors-credentials-wildcard | high | Credentials sent with wildcard origin |

---

## TLS/SSL Certificate Analysis

### Description
Parses X.509 certificates to extract subject, issuer, validity dates, SAN entries, and detects weak ciphers.

### Usage
Requires `tls_analysis` module integration.

### Output Interpretation
```
Certificate: example.com
  Issuer: Let's Encrypt
  Valid: 2026-01-01 to 2027-01-01
  Days until expiry: 365
  Self-signed: false
  Weak cipher: false
```

---

## WAF Detection

### Description
Identifies Web Application Firewalls from HTTP headers and response bodies. Supports Cloudflare, AWS WAF, Akamai, Imperva, Incapsula, and Sucuri.

### Usage
Automatically detected during probing.

### Output Interpretation
```
[WAF: Cloudflare] - cf-ray header present
[WAF: AWS WAF] - 403 error with request ID
```

---

## Cloud Provider Detection

### Description
Identifies hosting providers from response headers. Supports AWS, GCP, Azure, Cloudflare, Vercel, Netlify, Heroku, DigitalOcean, Linode, Akamai, and Fastly.

### Usage
Automatically detected from headers.

### Output Interpretation
```
Cloud: AWS (CloudFront) - Region: US
Cloud: Vercel - Deployment URL: my-app.vercel.app
```

---

## HTTP Method Enumeration

### Description
Tests for enabled HTTP methods (PUT, DELETE, TRACE, etc.) when aggressive mode is enabled.

### Usage
```bash
openxos-probe --input targets.txt --aggressive
```

### Output Interpretation
```
Allowed: GET, HEAD, POST, OPTIONS
Dangerous: PUT, DELETE
Findings: enabled-put (Medium), enabled-delete (Medium)
```

---

## Cookie Security Analysis

### Description
Analyzes Set-Cookie headers for missing HttpOnly, Secure, and SameSite flags. Flags session cookies without proper protection.

### Usage
Automatically analyzed during scans.

### Output Interpretation
| Finding | Severity | Description |
|---------|----------|-------------|
| session-cookie-missing-httponly | high | Session cookie accessible via JavaScript |
| cookie-missing-samesite | low | Cookie lacks CSRF protection |

---

## SSRF Vector Detection

### Description
Tests URL parameters for Server-Side Request Forgery vulnerabilities by checking against AWS metadata and localhost.

### Usage
```bash
openxos-probe --input targets.txt  # SSRF tested automatically (non-fast mode)
```

### Output Interpretation
```
SSRF Vulnerable: url, dest parameters detected
```

---

## Certificate Transparency Log Lookup

### Description
Queries crt.sh to discover subdomains from TLS certificates.

### Usage
```bash
openxos-probe --input targets.txt --ct-logs
```

### Output Interpretation
```
Certificate Transparency:
  Discovered: 15 subdomains
  Checked at: 2026-01-15T10:30:00Z
```

---

## Takeover Detection

### Description
Identifies vulnerable subdomain takeovers by matching response patterns against known service fingerprints.

### Usage
Automatically checked for dead subdomains returning specific error messages.

### Output Interpretation
```
Takeover: herokuapp.com (Heroku)
Fingerprint: "There is no app configured at that hostname"
```

---

## Rate Limit Detection

### Description
Parses rate limit headers (`X-RateLimit-*`, `Retry-After`) to detect API throttling.

### Usage
Automatically detected from responses.

### Output Interpretation
```
Rate Limit: detected
  Limit: 100 requests
  Remaining: 50
  Reset: 3600s
```

---

## WebSocket Detection

### Description
Tests common WebSocket paths for real-time communication endpoints. Detects `/ws`, `/websocket`, `/socket.io`, `/cable`, `/stream`, `/live`.

### Usage
```bash
openxos-probe --input targets.txt  # (default - non-fast mode)
```

### Output Interpretation
```
WebSocket detected at /ws (status: 101)
```

---

## GraphQL Detection

### Description
Probes GraphQL endpoints and checks for introspection enabled. Detects mutations, subscriptions, and GraphiQL availability.

### Usage
Automatically detected during probing (non-fast mode).

### Output Interpretation
```
GraphQL: /graphql
  Introspection: enabled
  Mutations: yes
  GraphiQL: available
```

---

## API Documentation Discovery

### Description
Discovers exposed API documentation from OpenAPI/Swagger specs. Supports `/swagger.json`, `/openapi.yaml`, `/docs`, and other common paths.

### Usage
Automatically detected during probing (non-fast mode).

### Output Interpretation
```
API Docs: /openapi.json
  Type: OpenAPI 3.0
  Title: My API
  Version: 1.0.0
  Endpoints: 42
```

---

## Cache Analysis

### Description
Analyzes HTTP cache headers (Cache-Control, ETag, Last-Modified) to detect misconfigurations including cache poisoning vectors.

### Usage
Automatically analyzed during scans.

### Output Interpretation
| Finding ID | Severity | Description |
|-----------|----------|-------------|
| cache-missing-control | medium | No Cache-Control header |
| cache-private-shared | low | Private resource cached globally |
| etag-missing | low | No ETag or Last-Modified |

---

## Content Type Mismatch

### Description
Detects when server declares incorrect Content-Type (e.g., HTML in JSON response), enabling XSS or other injection attacks.

### Usage
Automatically detected during probing.

---

## HTTP/2 and HTTP/3 Detection

### Description
Detects HTTP protocol versions from responses. Parses `alt-svc` headers to identify HTTP/3 advertisement.

### Usage
Automatically detected from server responses.

### Output Interpretation
```
HTTP Version: HTTP/2
HTTP/3 Advertised: true (port: 443)
```

---

## Monitoring Mode

### Description
Runs continuous scans at configurable intervals with webhook notifications.

### Usage
```bash
openxos-probe --input targets.txt --monitor --interval 300 --webhook https://discord.com/api/webhooks/...
```

### Output Interpretation
```
[2026-01-15 10:00:00] Scan started...
Scan complete in 45.2s | Alive: 120 | High findings: 5
>> Webhook notification sent
Waiting 300 seconds until next scan...
```

---

## Database Storage

### Description
Stores all probe results in SQLite for historical analysis and querying.

### Usage
```bash
openxos-probe --input targets.txt --db results.db
```

### Querying Results
Connect to the database to query findings:
```sql
SELECT domain, finding_id, severity FROM security_findings WHERE severity = 'high';
SELECT domain, technology_name FROM technologies WHERE technology_name LIKE '%nginx%';
```
