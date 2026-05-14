use crate::cli::{Args, OutputFormat};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_CONFIG_FILE: &str = "openxos-probe.toml";

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub input: PathBuf,
    pub output: OutputFormat,
    pub output_file: Option<PathBuf>,
    pub db: PathBuf,
    pub concurrency: usize,
    pub timeout_secs: u64,
    pub retries: u8,
    pub user_agent: String,
    pub insecure: bool,
    pub ct_logs: bool,
    pub monitor: bool,
    pub interval: u64,
    pub webhook: Option<String>,
    #[allow(dead_code)]
    pub cve_lookup: bool,
    pub fast: bool,
    pub aggressive: bool,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct FileConfig {
    input: Option<PathBuf>,
    output: Option<OutputFormat>,
    output_file: Option<PathBuf>,
    db: Option<PathBuf>,
    concurrency: Option<usize>,
    timeout_secs: Option<u64>,
    retries: Option<u8>,
    user_agent: Option<String>,
    insecure: Option<bool>,
    ct_logs: Option<bool>,
    monitor: Option<bool>,
    interval: Option<u64>,
    webhook: Option<String>,
    cve_lookup: Option<bool>,
    fast: Option<bool>,
    aggressive: Option<bool>,
}

impl AppConfig {
    pub fn resolve(args: &Args) -> Result<Self> {
        let from_file = load_file_config(args.config.as_deref())?;
        let input = args
            .input
            .clone()
            .or(from_file.input)
            .context("missing required input file: use --input or set input in config file")?;
        let output = args
            .output
            .or(from_file.output)
            .unwrap_or(OutputFormat::Terminal);
        let output_file = args.output_file.clone().or(from_file.output_file);
        let db = args
            .db
            .clone()
            .or(from_file.db)
            .unwrap_or_else(|| PathBuf::from("openxos-probe.db"));
        let concurrency = args
            .concurrency
            .or(from_file.concurrency)
            .unwrap_or(50)
            .clamp(1, 500);
        let timeout_secs = args
            .timeout_secs
            .or(from_file.timeout_secs)
            .unwrap_or(10)
            .clamp(1, 300);
        let retries = args.retries.or(from_file.retries).unwrap_or(1);
        let user_agent = args
            .user_agent
            .clone()
            .or(from_file.user_agent)
            .unwrap_or_else(|| "openxos-probe/0.1".to_string());
        let insecure = if args.insecure {
            true
        } else if args.secure {
            false
        } else {
            from_file.insecure.unwrap_or(false)
        };
        let ct_logs = args.ct_logs || from_file.ct_logs.unwrap_or(false);
        let monitor = args.monitor || from_file.monitor.unwrap_or(false);
        let interval = Some(args.interval)
            .or(from_file.interval)
            .unwrap_or(60)
            .max(1);
        let webhook = args.webhook.clone().or(from_file.webhook);
        let cve_lookup = args.cve_lookup || from_file.cve_lookup.unwrap_or(false);
        let fast = args.fast || from_file.fast.unwrap_or(false);
        let aggressive = args.aggressive || from_file.aggressive.unwrap_or(false);

        Ok(Self {
            input,
            output,
            output_file,
            db,
            concurrency,
            timeout_secs,
            retries,
            user_agent,
            insecure,
            ct_logs,
            monitor,
            interval,
            webhook,
            cve_lookup,
            fast,
            aggressive,
        })
    }
}

fn load_file_config(path: Option<&Path>) -> Result<FileConfig> {
    let selected = path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_FILE));
    if !selected.exists() {
        return Ok(FileConfig::default());
    }
    let raw = fs::read_to_string(&selected)
        .with_context(|| format!("failed to read config file {:?}", selected))?;
    let parsed: FileConfig =
        toml::from_str(&raw).with_context(|| format!("invalid TOML in {:?}", selected))?;
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::FileConfig;

    #[test]
    fn default_file_config_has_all_none() {
        let cfg = FileConfig::default();
        assert!(cfg.input.is_none());
        assert!(cfg.output.is_none());
        assert!(cfg.output_file.is_none());
        assert!(cfg.db.is_none());
        assert!(cfg.concurrency.is_none());
        assert!(cfg.timeout_secs.is_none());
        assert!(cfg.retries.is_none());
        assert!(cfg.user_agent.is_none());
        assert!(cfg.insecure.is_none());
        assert!(cfg.monitor.is_none());
        assert!(cfg.interval.is_none());
        assert!(cfg.webhook.is_none());
        assert!(cfg.cve_lookup.is_none());
        assert!(cfg.fast.is_none());
    }

    #[test]
    fn file_config_deserializes_from_toml() {
        let raw = r#"
input = "targets.txt"
output = "json"
concurrency = 80
timeout_secs = 5
retries = 3
user_agent = "custom-agent/1.0"
insecure = true
monitor = true
interval = 120
webhook = "https://example.com/webhook"
cve_lookup = true
"#;
        let cfg: FileConfig = toml::from_str(raw).unwrap();
        assert_eq!(cfg.concurrency, Some(80));
        assert_eq!(cfg.timeout_secs, Some(5));
        assert_eq!(cfg.retries, Some(3));
        assert_eq!(cfg.user_agent, Some("custom-agent/1.0".to_string()));
        assert_eq!(cfg.insecure, Some(true));
        assert_eq!(cfg.monitor, Some(true));
        assert_eq!(cfg.interval, Some(120));
        assert_eq!(cfg.webhook, Some("https://example.com/webhook".to_string()));
        assert_eq!(cfg.cve_lookup, Some(true));
    }

    #[test]
    fn file_config_all_fields_optional() {
        let raw = "input = \"targets.txt\"";
        let cfg: FileConfig = toml::from_str(raw).unwrap();
        assert!(cfg.output.is_none());
        assert!(cfg.output_file.is_none());
        assert!(cfg.db.is_none());
        assert!(cfg.concurrency.is_none());
        assert!(cfg.timeout_secs.is_none());
        assert!(cfg.retries.is_none());
        assert!(cfg.user_agent.is_none());
        assert!(cfg.insecure.is_none());
        assert!(cfg.monitor.is_none());
        assert!(cfg.interval.is_none());
        assert!(cfg.webhook.is_none());
        assert!(cfg.cve_lookup.is_none());
        assert!(cfg.fast.is_none());
    }

    #[test]
    fn app_config_resolve_uses_args_input() {
        let args = super::Args {
            input: Some(std::path::PathBuf::from("targets.txt")),
            output: Some(super::OutputFormat::Json),
            output_file: None,
            db: None,
            concurrency: Some(100),
            timeout_secs: Some(8),
            retries: Some(2),
            user_agent: Some("CustomUA".to_string()),
            insecure: false,
            secure: false,
            config: None,
            ct_logs: false,
            monitor: false,
            interval: 60,
            webhook: None,
            cve_lookup: false,
            fast: false,
            aggressive: false,
            query: None,
            query_tech: None,
            query_findings: None,
        };
        let cfg = super::AppConfig::resolve(&args).unwrap();
        assert_eq!(cfg.concurrency, 100); // Args take precedence
        assert_eq!(cfg.timeout_secs, 8); // Args take precedence
        assert_eq!(cfg.retries, 2); // Args take precedence
        assert_eq!(cfg.output, super::OutputFormat::Json);
        assert_eq!(cfg.user_agent, "CustomUA");
    }

    #[test]
    fn app_config_resolve_clamp_concurrency() {
        let args = super::Args {
            input: Some(std::path::PathBuf::from("t.txt")),
            output: None,
            output_file: None,
            db: None,
            concurrency: Some(1000),
            timeout_secs: None,
            retries: None,
            user_agent: None,
            insecure: false,
            secure: false,
            config: None,
            ct_logs: false,
            monitor: false,
            interval: 60,
            webhook: None,
            cve_lookup: false,
            fast: false,
            aggressive: false,
            query: None,
            query_tech: None,
            query_findings: None,
        };
        let cfg = super::AppConfig::resolve(&args).unwrap();
        assert_eq!(cfg.concurrency, 500);

        let args2 = super::Args {
            concurrency: Some(0),
            ..args.clone()
        };
        let cfg2 = super::AppConfig::resolve(&args2).unwrap();
        assert_eq!(cfg2.concurrency, 1);
    }

    #[test]
    fn app_config_resolve_clamp_timeout() {
        let args = super::Args {
            input: Some(std::path::PathBuf::from("t.txt")),
            output: None,
            output_file: None,
            db: None,
            concurrency: None,
            timeout_secs: Some(999),
            retries: None,
            user_agent: None,
            insecure: false,
            secure: false,
            config: None,
            ct_logs: false,
            monitor: false,
            interval: 60,
            webhook: None,
            cve_lookup: false,
            fast: false,
            aggressive: false,
            query: None,
            query_tech: None,
            query_findings: None,
        };
        let cfg = super::AppConfig::resolve(&args).unwrap();
        assert_eq!(cfg.timeout_secs, 300);

        let args2 = super::Args {
            timeout_secs: Some(0),
            ..args.clone()
        };
        let cfg2 = super::AppConfig::resolve(&args2).unwrap();
        assert_eq!(cfg2.timeout_secs, 1);
    }

    #[test]
    fn app_config_insecure_flag_overrides() {
        let args = super::Args {
            input: Some(std::path::PathBuf::from("t.txt")),
            output: None,
            output_file: None,
            db: None,
            concurrency: None,
            timeout_secs: None,
            retries: None,
            user_agent: None,
            insecure: true,
            secure: false,
            config: None,
            ct_logs: false,
            monitor: false,
            interval: 60,
            webhook: None,
            cve_lookup: false,
            fast: false,
            aggressive: false,
            query: None,
            query_tech: None,
            query_findings: None,
        };
        let cfg = super::AppConfig::resolve(&args).unwrap();
        assert!(cfg.insecure);

        let args2 = super::Args {
            insecure: false,
            secure: true,
            ..args
        };
        let cfg2 = super::AppConfig::resolve(&args2).unwrap();
        assert!(!cfg2.insecure);
    }

    #[test]
    fn app_config_resolve_missing_input_fails() {
        let args = super::Args {
            input: None,
            output: None,
            output_file: None,
            db: None,
            concurrency: None,
            timeout_secs: None,
            retries: None,
            user_agent: None,
            insecure: false,
            secure: false,
            config: None,
            ct_logs: false,
            monitor: false,
            interval: 60,
            webhook: None,
            cve_lookup: false,
            fast: false,
            aggressive: false,
            query: None,
            query_tech: None,
            query_findings: None,
        };
        let err = super::AppConfig::resolve(&args).unwrap_err();
        assert!(err.to_string().contains("input"));
    }

    #[test]
    fn load_file_config_missing_file_returns_default() {
        let result = super::load_file_config(Some(std::path::Path::new("nonexistent.toml")));
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert!(cfg.input.is_none());
    }
}
