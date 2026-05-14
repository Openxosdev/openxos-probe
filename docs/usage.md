# Usage

## Basic

```bash
cargo run -- --input subdomains.txt
```

## Output selection

```bash
# Terminal (default)
cargo run -- --input subdomains.txt --output terminal

# JSON
cargo run -- --input subdomains.txt --output json --output-file artifacts/results.json

# CSV
cargo run -- --input subdomains.txt --output csv --output-file artifacts/results.csv
```

## Operational flags

```bash
cargo run -- \
  --input subdomains.txt \
  --concurrency 100 \
  --timeout-secs 8 \
  --retries 2 \
  --user-agent "openxos-probe/0.1 custom" \
  --db artifacts/openxos-probe.db
```

## TLS behavior

```bash
# accept invalid certs
cargo run -- --input subdomains.txt --insecure

# force secure mode (overrides config)
cargo run -- --input subdomains.txt --secure
```

## Scan modes

```bash
# Fast mode - skip slow checks (WebSocket, GraphQL, API docs, SSRF)
cargo run -- --input subdomains.txt --fast

# Aggressive mode - enable HTTP method enumeration
cargo run -- --input subdomains.txt --aggressive
```

## Extended features

```bash
# Certificate Transparency log lookup
cargo run -- --input subdomains.txt --ct-logs

# Monitoring mode with webhook notifications
cargo run -- --input subdomains.txt --monitor --interval 300 --webhook https://discord.com/api/webhooks/...

# CVE lookup for detected technologies
cargo run -- --input subdomains.txt --cve-lookup

# Custom config file
cargo run -- --input subdomains.txt --config custom-config.toml
```
