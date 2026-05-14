# Configuration

`openxos-probe` reads config with this precedence:

1. Built-in defaults
2. TOML config file (`openxos-probe.toml`, or `--config`)
3. CLI flags

## Supported keys

```toml
input = "subdomains.txt"
output = "terminal"         # terminal | json | csv
output_file = "results.json"
db = "openxos-probe.db"
concurrency = 50
timeout_secs = 10
retries = 1
user_agent = "openxos-probe/0.1"
insecure = false
ct_logs = false
monitor = false
interval = 60
webhook = "https://discord.com/api/webhooks/..."
cve_lookup = false
fast = false
aggressive = false
```

## Notes

- `input` must be provided in either config or CLI.
- `concurrency` and `timeout_secs` are clamped to minimum `1`.
- `--insecure` forces `insecure = true`.
- `--secure` forces `insecure = false`.
- If both flags are absent, `insecure` comes from config/default.
- `fast = true` skips WebSocket, GraphQL, API docs, SSRF, and favicon probes.
- `aggressive = true` enables HTTP method enumeration for PUT/DELETE/TRACE.

## Example layered usage

```bash
# base config in openxos-probe.toml
cargo run -- --concurrency 120 --output json --output-file artifacts/override.json
```
