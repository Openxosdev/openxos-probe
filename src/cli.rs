use clap::{Parser, ValueEnum};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "openxos-probe",
    about = "HTTP service analysis and technology fingerprinting for bug bounty hunters",
    long_about = "Transforms raw subdomain lists into actionable target intelligence through HTTP probing, technology fingerprinting, and security analysis.

Examples:
  openxos-probe --input subdomains.txt
  openxos-probe --input subdomains.txt --output json --output-file results.json
  openxos-probe --input subdomains.txt --concurrency 100 --timeout-secs 8

For more information, visit: https://github.com/Openxosdev/openxos-probe"
)]
pub struct Args {
    #[arg(short, long, value_name = "FILE", help = "Input file containing subdomain list (one per line)")]
    pub input: Option<PathBuf>,

    #[arg(short, long, value_enum, help = "Output format: terminal, json, or csv")]
    pub output: Option<OutputFormat>,

    #[arg(long, value_name = "FILE", help = "Output file path (writes to stdout if not specified)")]
    pub output_file: Option<PathBuf>,

    #[arg(long, value_name = "FILE", help = "SQLite database path for persistent storage")]
    pub db: Option<PathBuf>,

    #[arg(
        short = 'c',
        long = "concurrency",
        value_name = "N",
        help = "Maximum concurrent connections (1-500, default: 50)"
    )]
    pub concurrency: Option<usize>,

    #[arg(
        long = "timeout-secs",
        value_name = "SECONDS",
        help = "Request timeout in seconds (1-300, default: 10)"
    )]
    pub timeout_secs: Option<u64>,

    #[arg(long = "retries", value_name = "N", help = "Number of retry attempts on failure (default: 1)")]
    pub retries: Option<u8>,

    #[arg(
        long = "user-agent",
        value_name = "STRING",
        help = "Custom User-Agent string"
    )]
    pub user_agent: Option<String>,

    #[arg(
        long,
        help = "Allow invalid/self-signed TLS certificates (default: validate certificates)"
    )]
    pub insecure: bool,

    #[arg(
        long,
        conflicts_with = "insecure",
        help = "Force TLS certificate validation (overrides config file)"
    )]
    pub secure: bool,

    #[arg(
        long,
        value_name = "FILE",
        help = "Path to TOML configuration file"
    )]
    pub config: Option<PathBuf>,

    #[arg(
        long,
        help = "Query Certificate Transparency logs for subdomains (adds network overhead)"
    )]
    pub ct_logs: bool,

    #[arg(long, help = "Enable continuous monitoring mode")]
    pub monitor: bool,

    #[arg(long, value_name = "SECONDS", default_value = "60", help = "Monitoring interval in seconds")]
    pub interval: u64,

    #[arg(long, value_name = "URL", help = "Webhook URL for scan notifications")]
    pub webhook: Option<String>,

    #[arg(long, help = "Enable on-demand CVE lookup for detected technologies")]
    pub cve_lookup: bool,

    #[arg(long, help = "Fast mode - skip slow checks (WebSocket, GraphQL, API docs, SSRF)")]
    pub fast: bool,

    #[arg(long, help = "Aggressive mode - enable HTTP method enumeration and other intrusive checks")]
    pub aggressive: bool,
}

#[derive(Clone, Copy, Debug, ValueEnum, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[doc(hidden)]
pub enum OutputFormat {
    #[value(rename_all = "lowercase")]
    Terminal,
    #[value(rename_all = "lowercase")]
    Json,
    #[value(rename_all = "lowercase")]
    Csv,
}
