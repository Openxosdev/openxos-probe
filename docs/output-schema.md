# Output Schema Contracts

This document defines the schema for JSON and CSV outputs.

## JSON contract (`schema_version = "1.0"`)

Top-level object:

- `schema_version` (string)
- `generated_at` (RFC3339 timestamp string)
- `summary` (object)
- `results` (array of probe result objects)

`summary`:

- `scanned` (number)
- `alive` (number)
- `dead` (number)
- `findings_total` (number)
- `findings_high` (number)
- `findings_medium` (number)
- `findings_low` (number)

`results[]` includes:

- `domain` (string)
- `probe_timestamp` (RFC3339 string)
- `alive` (boolean)
- `protocol` (string | null) - "http" or "https"
- `final_url` (string | null)
- `status_code` (number | null)
- `response_time_ms` (number | null)
- `error` (string | null)
- `technologies` (array)
  - `name` (string)
  - `confidence` (number, 0-100)
  - `evidence` (array of strings)
  - `version` (string | null)
  - `is_dev_mode` (boolean)
- `security_findings` (array)
  - `id` (string)
  - `category` (string) - "security_headers" | "information_disclosure"
  - `severity` (string) - "high" | "medium" | "low"
  - `title` (string)
  - `explanation` (string)
  - `evidence` (string)
- `waf` (object | null)
  - `name` (string | null) - "Cloudflare", "Akamai", "Imperva", etc.
  - `blocked` (boolean)
  - `evidence` (string)
- `favicon_hash` (string | null) - MD5 hash of favicon.ico
- `trace_enabled` (boolean | null) - HTTP TRACE method status
- `cookies` (array of strings) - Cookie names extracted from Set-Cookie headers
- `allowed_http_methods` (array of strings) - HTTP methods allowed (aggressive mode)
- `dangerous_http_methods` (array of strings) - PUT, DELETE, etc.
- `rate_limit` (object | null)
  - `limit` (number | null)
  - `remaining` (number | null)
  - `reset_seconds` (number | null)
- `cloud_info` (object | null)
  - `provider` (string | null)
  - `service` (string | null)
  - `region` (string | null)
- `websocket` (object | null)
  - `path` (string)
  - `status` (number)
- `graphql` (object | null)
  - `endpoint` (string)
  - `introspection_enabled` (boolean)
  - `has_mutations` (boolean)
  - `has_subscriptions` (boolean)
  - `graphiql_available` (boolean)
- `api_docs` (array)
  - `path` (string)
  - `doc_type` (string)
  - `title` (string | null)
  - `version` (string | null)
  - `endpoint_count` (number)
- `ssrf_info` (object | null)
  - `vulnerable_parameters` (array of strings)
  - `checked_at` (string)
- `ct_info` (object | null) - Certificate Transparency
  - `subdomains` (array of strings)
  - `checked_at` (string)
- `cache` (object | null)
  - `has_cache_control` (boolean)
  - `has_etag` (boolean)
  - `cacheable` (boolean)
- `timing` (object | null)
  - `ttfb_ms` (number)
  - `total_ms` (number)
  - `download_speed_bps` (number | null)

## CSV contract

Columns:

- `domain`
- `probe_timestamp`
- `alive`
- `protocol`
- `final_url`
- `status_code`
- `response_time_ms`
- `error`
- `technologies` (JSON-encoded array)
- `waf_name`
- `favicon_hash`
- `trace_enabled`
- `cookies` (JSON-encoded array)
- `findings_high`
- `findings_medium`
- `findings_low`
- `finding_ids` (`;`-delimited finding IDs)
- `security_findings` (JSON-encoded array)

## Example JSON

```json
{
  "schema_version": "1.0",
  "generated_at": "2026-01-15T10:30:00Z",
  "summary": {
    "scanned": 100,
    "alive": 45,
    "dead": 55,
    "findings_total": 23,
    "findings_high": 5,
    "findings_medium": 12,
    "findings_low": 6
  },
  "results": [
    {
      "domain": "api.example.com",
      "probe_timestamp": "2026-01-15T10:30:01Z",
      "alive": true,
      "protocol": "https",
      "final_url": "https://api.example.com/",
      "status_code": 200,
      "response_time_ms": 85,
      "error": null,
      "technologies": [
        {
          "name": "nginx",
          "confidence": 35,
          "evidence": ["header:server~nginx"]
        },
        {
          "name": "node-js",
          "confidence": 35,
          "evidence": ["header:x-powered-by~express"]
        }
      ],
      "security_findings": [
        {
          "id": "missing-content-security-policy",
          "category": "security_headers",
          "severity": "medium",
          "title": "Missing Content-Security-Policy",
          "explanation": "Without CSP, malicious scripts can execute more easily if an injection bug exists.",
          "evidence": "content-security-policy not present"
        },
        {
          "id": "exposed-file-actuator-env",
          "category": "information_disclosure",
          "severity": "high",
          "title": "Spring Boot actuator exposed",
          "explanation": "Publicly accessible debug/config endpoints can leak internal deployment details.",
          "evidence": "path=/actuator/env status=200 snippet=property"
        }
      ],
      "waf": {
        "name": "Cloudflare",
        "blocked": false,
        "evidence": "cf-ray header present"
      },
      "favicon_hash": "a1b2c3d4e5f6...",
      "trace_enabled": false,
      "cookies": ["session_id", "csrf_token"]
    }
  ]
}
```

## Example CSV Row

```csv
domain,probe_timestamp,alive,protocol,final_url,status_code,response_time_ms,error,technologies,waf_name,favicon_hash,trace_enabled,cookies,findings_high,findings_medium,findings_low,finding_ids,security_findings
api.example.com,2026-01-15T10:30:01Z,true,https,https://api.example.com/,200,85,,[{"name":"nginx","confidence":35,"evidence":["header:server~nginx"]},{"name":"node-js","confidence":35,"evidence":["header:x-powered-by~express"]}],Cloudflare,a1b2c3d4e5f6...,false,["session_id","csrf_token"],1,1,0,missing-content-security-policy;exposed-file-actuator-env,[{"id":"missing-content-security-policy",...},{"id":"exposed-file-actuator-env",...}]
```

## Technology Signature Format

Signature files use JSON format in `signatures/` directory:

```json
[
  {
    "name": "nginx",
    "headers": [
      { "name": "server", "contains": "nginx" }
    ],
    "body": [],
    "path_probes": []
  },
  {
    "name": "wordpress",
    "headers": [],
    "body": ["wp-content", "wordpress"],
    "path_probes": [
      {
        "path": "/wp-login.php",
        "status_any_of": [200, 302],
        "body_contains": ["wordpress"]
      }
    ]
  }
]
```

### Signature Fields

- `name` (required): Technology name
- `headers` (optional): Header-based detection rules
- `body` (optional): Body content patterns
- `path_probes` (optional): Additional path requests

### Header Rule Fields

- `name`: Header name (case-insensitive)
- `contains`: Pattern to match in header value

### Path Probe Fields

- `path`: URL path to probe (must start with `/`)
- `status_any_of`: Expected HTTP status codes
- `body_contains`: Patterns expected in response body
