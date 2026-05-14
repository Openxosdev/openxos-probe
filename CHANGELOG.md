# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.1.2] - 2026-05-14 — Crimson Probe

### Added
- `--version` flag with code name ("Crimson Probe")
- `--query` flag for custom SQL queries against database
- `--query-tech` flag to find domains by detected technology
- `--query-findings` flag to find domains by security finding severity
- Error details for dead hosts now shown in progress status line
- Signatures auto-discovered from cwd, exe dir, or OPENXOS_SIGNATURES env var

### Fixed
- `--version` flag not recognized
- Dead hosts showing no error reason (timeout/DNS/refused now displayed)
- Technology signatures warning UX improved

## [0.1.0] - 2026-05-10

### Added

#### Core Probing
- Async HTTP/HTTPS probing with `tokio::join!`
- Parallel protocol testing (both fired simultaneously)
- DNS caching with DashMap (5-minute TTL)
- Connection pooling (`pool_max_idle_per_host(10)`)
- TCP optimization (`tcp_nodelay`)
- Configurable concurrency (default 50, max 500)
- Timeout and retry configuration

#### Technology Detection
- 200+ technology signatures
- Aho-Corasick SIMD pattern matching (10x faster)
- 50 path probes in parallel (`buffer_unordered(20)`)
- Favicon hashing (MD5)
- JS framework detection (React, Vue, Angular, Next.js, Svelte, Nuxt)
- Source map detection (Webpack dev mode)

#### Security Analysis
- WAF detection (Cloudflare, Akamai, Imperva, AWS WAF, Sucuri, Fastly, Incapsula)
- Security headers analysis (CSP, HSTS, X-Frame-Options, X-Content-Type, Referrer-Policy, Permissions-Policy)
- Cookie security analysis (HttpOnly, Secure, SameSite flags)
- Cache analysis for sensitive endpoints
- Information disclosure (.env, .git/config, phpinfo, stack traces)
- TRACE method detection (XST)
- TLS certificate analysis (subject, issuer, SAN, expiry, key size)
- Redirect chain analysis (HTTPS downgrade detection)
- Content-Type mismatch detection
- Rate limit intelligence (`x-ratelimit-*`, `x-rate-limit-*` headers)

#### API Discovery
- WebSocket detection (/ws, /socket.io, /cable)
- GraphQL introspection
- OpenAPI/Swagger discovery (17 paths)
- HTTP method enumeration (with `--aggressive` flag)

#### Cloud & Infrastructure
- Cloud provider detection (AWS, GCP, Azure, Vercel, Netlify, Cloudflare, DigitalOcean, Heroku)
- Certificate transparency (crt.sh enumeration)
- Subdomain takeover detection (S3, Heroku, GitHub Pages, Bitbucket, GitLab, Vercel, Netlify)
- SSRF vector detection (23 parameters, 5 internal targets)
- CVE lookup (on-demand)

#### Operations
- Continuous monitoring mode (`--monitor --interval`)
- Webhook notifications (Discord/Slack)
- SQLite persistence with query API
- Multiple output formats (Terminal, JSON, CSV)
- Configuration file support (TOML)

#### CLI Flags
- `--fast` - Skip slow checks for quick reconnaissance
- `--aggressive` - Enable HTTP method enumeration
- `--monitor` - Continuous monitoring mode
- `--interval` - Monitoring interval in seconds
- `--webhook` - Webhook URL for notifications
- `--ct-logs` - Certificate transparency lookup
- `--cve-lookup` - On-demand CVE lookup
- `--insecure` - Skip TLS validation

### Performance
- Parallel HTTP/HTTPS via `tokio::join!`
- DNS caching (DashMap, 5-min TTL)
- SIMD pattern matching (Aho-Corasick)
- Async DB writes via `mpsc::unbounded_channel`
- Fast mode for quick scans (~8-10s for 10 domains)
- Normal mode (~12-15s) and aggressive mode (~20-25s)

### Dependencies
- `reqwest` - HTTP client with rustls-tls
- `tokio` - Async runtime
- `rusqlite` - SQLite database
- `dashmap` - Concurrent DNS cache
- `aho-corasick` - SIMD pattern matching
- `x509-parser` - TLS certificate parsing
- `tokio-rustls` - TLS stream access
- `clap` - CLI argument parsing
- `serde` - Serialization
- `chrono` - Date/time handling
- `indicatif` - Progress bars

### Testing
- 144 tests passing
- Unit tests for core components
- Integration tests for workflows
- Mock HTTP server tests

### Fixed
- Multiple compilation errors resolved
- Test failures (111 → 144 passing)
- Dead code warnings suppressed
- Performance bottlenecks (parallel path probes)

---

## [0.0.0] - 2026-05-08

### Added
- Initial project structure
- Basic HTTP probing
- Technology fingerprinting framework
- Security header analysis
