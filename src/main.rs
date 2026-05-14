use anyhow::Result;
use clap::Parser;
use colored::*;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::{Duration, Instant};

mod cli;
mod config;
mod input;
mod output;
mod probe;
mod security;
mod storage;
mod technology;
mod tls_analysis;

use crate::cli::Args;
use crate::config::AppConfig;
use crate::output::Summary;
use probe::ProbeConfig;

async fn run_single_scan(
    domains: Vec<String>,
    probe_config: ProbeConfig,
) -> Result<Vec<probe::ProbeResult>> {
    probe::probe_domains(domains, probe_config, |_done, _result| {}).await
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    if args.query.is_some() || args.query_tech.is_some() || args.query_findings.is_some() {
        return run_query_mode(&args);
    }

    let config = AppConfig::resolve(&args)?;

    print_banner();

    if config.monitor {
        run_monitoring_mode(&config).await?;
    } else {
        run_single_scan_mode(&config).await?;
    }

    Ok(())
}

async fn run_monitoring_mode(config: &AppConfig) -> Result<()> {
    let parse_result = input::parse_domains(&std::fs::read_to_string(&config.input)?);
    let domains = parse_result.domains;

    if domains.is_empty() {
        println!("{}", "Error: No valid domains found in input.".red().bold());
        return Ok(());
    }

    let probe_config = ProbeConfig::from_config(config)?;
    let db = storage::Database::new(&config.db)?;

    println!("{}", ">> Monitoring Mode Enabled".cyan().bold());
    println!("  Interval: {} seconds", config.interval);
    println!("  Targets: {}\n", domains.len());

    loop {
        let scan_start = Instant::now();
        let run_meta = storage::RunMetadata::from_config(domains.len(), config);
        let run_id = db.create_analysis_run(&run_meta)?;

        println!(
            "{}",
            format!(
                "[{}] Scan started...",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S")
            )
            .yellow()
        );

        let results = run_single_scan(domains.clone(), probe_config.clone()).await?;

        db.persist_results(run_id, &results)?;
        db.finalize_analysis_run(run_id, results.len() as i64)?;
        output::write_output(config.output.clone(), config.output_file.clone(), &results)?;

        let elapsed = scan_start.elapsed().as_secs_f64();
        let alive_count = results.iter().filter(|r| r.alive).count();
        let findings_high = results
            .iter()
            .flat_map(|r| &r.security_findings)
            .filter(|f| f.severity == security::Severity::High)
            .count();

        println!(
            "{}",
            format!(
                "[{}] Scan complete in {:.1}s | Alive: {} | High findings: {}",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                elapsed,
                alive_count,
                findings_high
            )
            .green()
        );

        if let Some(webhook_url) = &config.webhook {
            let summary = Summary::from_results(&results);
            if let Err(e) =
                output::send_webhook_notification(webhook_url, &summary, domains.len(), elapsed)
                    .await
            {
                eprintln!("{} Webhook failed: {}", "Error:".red(), e);
            } else {
                println!("{} Webhook notification sent", ">>".cyan());
            }
        }

        println!("  Waiting {} seconds until next scan...\n", config.interval);
        tokio::time::sleep(Duration::from_secs(config.interval)).await;
    }
}

async fn run_single_scan_mode(config: &AppConfig) -> Result<()> {
    let parse_result = input::parse_domains(&std::fs::read_to_string(&config.input)?);
    let domains = parse_result.domains;

    println!("{}", "Input Statistics:".cyan().bold());
    println!("  # total lines     : {}", parse_result.stats.total_lines);
    println!("  # skipped empty   : {}", parse_result.stats.skipped_empty);
    println!(
        "  # skipped comments : {}",
        parse_result.stats.skipped_comments
    );
    println!(
        "  # skipped invalid  : {}",
        parse_result.stats.skipped_invalid
    );
    println!(
        "  # skipped sinkhole: {}",
        parse_result.stats.skipped_sinkhole
    );
    println!(
        "  # skipped reserved: {}",
        parse_result.stats.skipped_reserved
    );
    println!(
        "  # skipped dupe    : {}",
        parse_result.stats.skipped_duplicates
    );
    println!(
        "  # valid domains   : {}",
        parse_result.stats.valid_domains.to_string().green()
    );
    println!();

    if domains.is_empty() {
        println!("{}", "Error: No valid domains found in input.".red().bold());
        return Ok(());
    }

    let total = domains.len();
    let run_meta = storage::RunMetadata::from_config(total, config);
    let db = storage::Database::new(&config.db)?;
    let run_id = db.create_analysis_run(&run_meta)?;

    println!(
        "{} {}",
        ">>".cyan().bold(),
        format!("Probing {} targets...", total).yellow()
    );
    println!();

    let mp = MultiProgress::new();
    let pb = mp.add(ProgressBar::new(total as u64));
    pb.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed_precise}] [{bar:40}] {pos}/{len} ({per_sec}) {msg}")?
            .progress_chars("██▒▒"),
    );

    let probe_config = ProbeConfig::from_config(config)?;
    let scan_start = Instant::now();
    let results = probe::probe_domains(domains, probe_config, |_done, result| {
        let status = if result.alive {
            "ALIVE".green()
        } else {
            "DEAD".red()
        };
        let tech_count = result.technologies.len();
        let finding_count = result.security_findings.len();
        let waf_info = result
            .waf
            .as_ref()
            .and_then(|w| w.name.as_ref())
            .map(|n| n.as_str())
            .unwrap_or("-");

        let finding_tag = if finding_count > 0 {
            format!("[{} findings]", finding_count).yellow().to_string()
        } else {
            String::new()
        };

        let waf_tag = if waf_info != "-" {
            format!("[waf:{}]", waf_info).cyan().to_string()
        } else {
            String::new()
        };

        let error_tag = if let Some(ref err) = result.error {
            format!("[err: {}]", err).red().to_string()
        } else {
            String::new()
        };

        pb.set_message(format!(
            "{} {} {} {} {} {}",
            result.domain,
            status,
            format!("[{} tech]", tech_count),
            finding_tag,
            waf_tag,
            error_tag
        ));
        pb.inc(1);
    })
    .await?;
    let elapsed = scan_start.elapsed().as_secs_f64();

    pb.finish_with_message("Scan complete");
    println!();

    let alive_count = results.iter().filter(|r| r.alive).count();
    let findings_high = results
        .iter()
        .flat_map(|r| &r.security_findings)
        .filter(|f| f.severity == security::Severity::High)
        .count();
    let findings_medium = results
        .iter()
        .flat_map(|r| &r.security_findings)
        .filter(|f| f.severity == security::Severity::Medium)
        .count();
    let findings_low = results
        .iter()
        .flat_map(|r| &r.security_findings)
        .filter(|f| f.severity == security::Severity::Low)
        .count();

    println!("{}", "=== Scan Summary ===".cyan().bold());
    println!("  # scanned    : {}", total);
    println!("  # alive      : {}", alive_count.to_string().green());
    println!("  # dead       : {}", total - alive_count);
    println!(
        "  # findings   : high={}, medium={}, low={}",
        findings_high, findings_medium, findings_low
    );
    println!("  # time       : {:.2}s", elapsed);
    println!();

    if findings_high > 0 {
        println!("{}", "Action Required (High Severity):".red().bold());
        for result in &results {
            let has_high = result
                .security_findings
                .iter()
                .any(|f| f.severity == security::Severity::High);
            if has_high {
                println!(
                    "  - {} ({} findings)",
                    result.domain,
                    result.security_findings.len()
                );
            }
        }
        println!();
    }

    db.persist_results(run_id, &results)?;
    db.finalize_analysis_run(run_id, results.len() as i64)?;
    output::write_output(config.output.clone(), config.output_file.clone(), &results)?;

    if let Some(webhook_url) = &config.webhook {
        let summary = Summary::from_results(&results);
        if let Err(e) =
            output::send_webhook_notification(webhook_url, &summary, total, elapsed).await
        {
            eprintln!("{} Webhook failed: {}", "Error:".red(), e);
        } else {
            println!("{} Webhook notification sent", ">>".cyan());
        }
    }

    Ok(())
}

fn run_query_mode(args: &Args) -> Result<()> {
    let db_path = args.db.clone().unwrap_or_else(|| std::path::PathBuf::from("openxos-probe.db"));
    let db = storage::Database::new(&db_path)?;

    if let Some(sql) = &args.query {
        let results = db.query(sql)?;
        for row in &results {
            println!("{}", row.join(" | "));
        }
    } else if let Some(tech) = &args.query_tech {
        let domains = db.query_domains_with_tech(tech)?;
        for domain in domains {
            println!("{}", domain);
        }
    } else if let Some(severity) = &args.query_findings {
        let domains = db.query_domains_with_findings(severity)?;
        for domain in domains {
            println!("{}", domain);
        }
    }

    Ok(())
}

fn print_banner() {
    println!(
        "{}",
        r#"
   ██████  ██░ ██  ▒█████    ██████ ▄▄▄█████▓
  ▒██    ▒ ▓██░ ██▒▒██▒  ██▒▒██    ▒ ▓  ██▒ ▓▒
  ░ ▓██▄   ▒██▀▀██░▒██░  ██▒░ ▓██▄   ▒ ▓██░ ▒░
    ▒   ██▒░▓█    ▓█░▒██   ██░  ▒   ██▒░ ▓██▓ ░
  ▒██████▒▒░▓█▒░██▓░ ████▓▒░▒██████▒▒  ▒██▒ ░
  ▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░  ▒ ░░
  ░ ░▒  ░ ░ ▒ ░▒░ ░  ░ ▒ ▒░ ░ ░▒  ░ ░    ░
  ░  ░  ░   ░  ░░ ░░ ░ ░ ▒  ░  ░  ░    ░
        ░   ░  ░  ░    ░ ░        ░
      "#
        .cyan()
    );
    println!(
        "  {} — HTTP probing & technology fingerprinting\n",
        format!("openxos-probe v{}", env!("CARGO_PKG_VERSION")).bold()
    );
}
