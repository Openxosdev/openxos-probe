# Openxos-ghost Integration
*For openxos-probe v0.1.0*

`openxos-probe` can be used as a discovery/finding source for Openxos-ghost workflows.

## Recommended pipeline

1. Run probe with JSON output.
2. Ingest `results` and `summary` into Openxos-ghost job context.
3. Prioritize follow-up actions by:
   - `security_findings.severity` (`high` first)
   - technology confidence (`technologies[].confidence`)
4. Store scan metadata (`generated_at`, `schema_version`) for auditability.

## Example command

```bash
cargo run -- \
  --input subdomains.txt \
  --output json \
  --output-file artifacts/openxos-probe-report.json
```

## Example with all features

```bash
# Fast scan with aggressive checks
cargo run -- \
  --input subdomains.txt \
  --output json \
  --aggressive \
  --output-file artifacts/results.json

# Extended scan with CT logs
cargo run -- \
  --input subdomains.txt \
  --output json \
  --ct-logs \
  --cve-lookup \
  --output-file artifacts/extended-results.json
```

## Suggested ingestion mapping

- `target`: `results[].domain`
- `is_alive`: `results[].alive`
- `http_status`: `results[].status_code`
- `fingerprints`: `results[].technologies`
- `security_findings`: `results[].security_findings`
- `scan_summary`: `summary`
- `websocket`: `results[].websocket`
- `graphql`: `results[].graphql`
- `api_docs`: `results[].api_docs`
- `waf`: `results[].waf`
- `cloud_info`: `results[].cloud_info`
- `rate_limit`: `results[].rate_limit`

## Stability

Use `schema_version` to enforce parser compatibility in Openxos-ghost ingestion code.
