# openxos-probe

**HTTP reconnaissance & security analysis tool for bug bounty hunters**

[![License: MIT](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.80+-orange?style=flat-square)](https://rustlang.org)
[![Tests](https://img.shields.io/badge/tests-144-blue?style=flat-square)](https://github.com/Openxosdev/openxos-probe)
[![Build](https://img.shields.io/github/actions/workflow/status/Openxosdev/openxos-probe/tests.yml?style=flat-square)](https://github.com/Openxosdev/openxos-probe/actions)

---

## Overview

**openxos-probe** transforms subdomain lists into actionable intelligence through comprehensive HTTP probing, technology fingerprinting, and security analysis.

Built in Rust for extreme performance with 144 passing tests.

---

## Features

### Core Probing
- Async HTTP/HTTPS probing with `tokio::join!`
- Parallel protocol testing (both fired simultaneously)
- DNS caching with DashMap (5-min TTL)
- Connection pooling (10 idle per host)
- TCP optimization (`tcp_nodelay`)
- Configurable concurrency (default 50, max 500)

### Technology Detection
- 200+ tech signatures
- Aho-Corasick SIMD pattern matching (10x faster)
- 50 path probes in parallel
- Favicon hashing (MD5)
- JS framework detection (React, Vue, Angular, Next.js, Svelte)
- Source map detection

### Security Analysis
- WAF detection (Cloudflare, Akamai, Imperva, AWS WAF, etc.)
- Security headers (CSP, HSTS, X-Frame, Referrer-Policy)
- Cookie security (HttpOnly, Secure, SameSite)
- Cache analysis for sensitive endpoints
- Information disclosure (.env, .git/config, stack traces)
- TLS certificate analysis
- Redirect chain analysis
- Content-Type mismatch detection

### API Discovery
- WebSocket detection (/ws, /socket.io)
- GraphQL introspection
- OpenAPI/Swagger discovery (17 paths)
- HTTP method enumeration (with --aggressive)

### Cloud & Infrastructure
- Cloud provider detection (AWS, GCP, Azure, Vercel, Netlify, Cloudflare)
- Certificate transparency (crt.sh)
- Subdomain takeover detection
- SSRF vector detection
- Rate limit intelligence

### Operations
- Continuous monitoring mode
- Webhook notifications (Discord/Slack)
- SQLite persistence with query API
- Multiple output formats (Terminal, JSON, CSV)

---

## Installation

### Via Cargo (Recommended)

```bash
cargo install openxos-probe
openxos-probe --version
```

### From Source

```bash
git clone https://github.com/Openxosdev/openxos-probe
cd openxos-probe
cargo build --release
./target/release/openxos-probe --version
```

### Pre-built Binaries

Download from [Releases](https://github.com/Openxosdev/openxos-probe/releases)

| Platform | Download |
|----------|----------|
| Linux x86_64 | `openxos-probe-linux-amd64` |
| Windows | `openxos-probe.exe` |
| macOS | `openxos-probe-macos` |

---

## Quick Start

```bash
# Basic scan
openxos-probe --input subdomains.txt

# Fast mode (skip slow checks)
openxos-probe --input subdomains.txt --fast

# Aggressive mode (HTTP method enumeration)
openxos-probe --input subdomains.txt --aggressive

# JSON output
openxos-probe --input subdomains.txt --output json --output-file results.json

# High concurrency
openxos-probe --input subdomains.txt --concurrency 100 --timeout-secs 8
```

---

## Usage Examples

### Monitoring Mode

```bash
# Scan every hour with webhook
openxos-probe --input targets.txt --monitor --interval 3600 --webhook https://discord.com/api/webhooks/...

# Fast monitoring
openxos-probe --input targets.txt --monitor --interval 300 --fast
```

### Integration with openxos-ghost

```bash
# Chain tools
ghost web --target example.com -o subs.txt
openxos-probe --input subs.txt --output json

# With monitoring
ghost web --target example.com -o subs.txt
openxos-probe --input subs.txt --monitor --interval 1800 --webhook $WEBHOOK_URL
```

### Certificate Transparency

```bash
# Enable CT log lookup
openxos-probe --input targets.txt --ct-logs

# Combined with aggressive
openxos-probe --input targets.txt --ct-logs --aggressive
```

---

## CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-i, --input` | Required | Input file with domains |
| `-o, --output` | terminal | Output format |
| `--output-file` | stdout | Output file path |
| `-c, --concurrency` | 50 | Max concurrent connections |
| `--timeout-secs` | 10 | Request timeout |
| `--retries` | 1 | Retry attempts |
| `--fast` | false | Skip slow checks |
| `--aggressive` | false | HTTP method enumeration |
| `--monitor` | false | Continuous monitoring |
| `--interval` | 60 | Monitoring interval (seconds) |
| `--webhook` | - | Webhook URL |
| `--ct-logs` | false | Certificate transparency |
| `--cve-lookup` | false | On-demand CVE lookup |
| `--insecure` | false | Skip TLS validation |
| `--db` | probe.db | Database path |

---

## Configuration

Create `openxos-probe.toml`:

```toml
input = "subdomains.txt"
output = "json"
concurrency = 80
timeout_secs = 8
retries = 2
monitor = false
interval = 60
webhook = "https://discord.com/api/webhooks/..."
ct_logs = false
cve_lookup = false
fast = false
aggressive = false
```

Use: `openxos-probe --config openxos-probe.toml`

---

## Performance

| Mode | 10 Domains | Features |
|------|-----------|----------|
| Fast | ~8-10s | Core + Security Headers |
| Normal | ~12-15s | Full analysis |
| Aggressive | ~20-25s | + HTTP methods |

### Optimizations
- Parallel HTTP/HTTPS via `tokio::join!`
- DNS caching (DashMap, 5-min TTL)
- Connection pooling (10 idle per host)
- TCP `tcp_nodelay`
- SIMD pattern matching (Aho-Corasick)
- Async DB writes

---

## Security Findings

### High Severity
- Stack trace disclosure
- Session cookie missing HttpOnly
- HTTPS to HTTP downgrade
- Subdomain takeover
- CORS with wildcard + credentials

### Medium Severity
- Missing HSTS header
- Missing X-Frame-Options
- PUT/DELETE enabled
- Sensitive endpoint cached
- Cookie missing SameSite

### Low Severity
- Missing CSP header
- Server version disclosure
- X-Powered-By exposed

---

## Database Query

```bash
# Custom SQL query
openxos-probe --db results.db --query "SELECT domain, status FROM probes WHERE alive = 1"

# By technology
openxos-probe --db results.db --query-tech "nginx"

# By findings
openxos-probe --db results.db --query-findings
```

---

## Development

```bash
# Run tests
cargo test

# Format code
cargo fmt

# Lint
cargo clippy

# Build
cargo build --release
```

---

## Dependencies

Core: `reqwest`, `tokio`, `serde`, `rusqlite`

Performance: `dashmap`, `aho-corasick`, `x509-parser`

CLI: `clap`, `colored`, `indicatif`

---

## License

MIT License - Copyright (c) 2026-2027 Openxosdev

See [LICENSE](LICENSE) for details.

---

## Support

If this tool is useful for your security work, consider supporting development:

**Monero (XMR):**
```
49DDzakQJoKKq5caPdeZMH1JoC1GERzbnTw7RFx5Zq4xFLiXgkNgxuEau4rXH3f5V29cbXPB4bxk1dy1YKxAiwZ9LvkaUCv
```

---

## Links

- [GitHub](https://github.com/Openxosdev/openxos-probe)
- [Issues](https://github.com/Openxosdev/openxos-probe/issues)
- [Discussions](https://github.com/Openxosdev/openxos-probe/discussions)

---

**For authorized security testing only**