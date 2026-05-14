use crate::config::AppConfig;
use crate::probe::ProbeResult;
use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};
use tokio::sync::mpsc;

pub struct Database {
    conn: Mutex<Connection>,
    #[allow(dead_code)]
    writer: Mutex<Option<Arc<DbWriter>>>,
}

#[derive(Debug, Clone)]
pub struct RunMetadata {
    pub targets_total: i64,
    pub concurrency: i64,
    pub timeout_secs: i64,
    pub retries: i64,
    pub user_agent: String,
    pub insecure: bool,
}

const BATCH_SIZE: usize = 100;

#[allow(dead_code)]
pub struct DbWriter {
    sender: mpsc::UnboundedSender<ProbeResult>,
    shutdown_tx: Option<mpsc::UnboundedSender<()>>,
    run_id: i64,
}

#[allow(dead_code)]
impl DbWriter {
    pub fn new(db_path: &Path, run_id: i64) -> Result<Self> {
        let (result_tx, mut result_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, mut shutdown_rx) = mpsc::unbounded_channel();

        let db_path = db_path.to_path_buf();

        tokio::spawn(async move {
            let mut batch: Vec<ProbeResult> = Vec::with_capacity(BATCH_SIZE);
            let mut pending_write: Option<tokio::task::JoinHandle<Result<()>>> = None;
            let mut last_error: Option<String> = None;

            loop {
                tokio::select! {
                    Some(result) = result_rx.recv() => {
                        batch.push(result);
                        if batch.len() >= BATCH_SIZE {
                            let batch_to_write = std::mem::take(&mut batch);
                            batch = Vec::with_capacity(BATCH_SIZE);

                            if let Some(handle) = pending_write.take() {
                                match handle.await {
                                    Ok(Ok(())) => {}
                                    Ok(Err(e)) => {
                                        last_error = Some(format!("batch write failed: {}", e));
                                    }
                                    Err(e) => {
                                        last_error = Some(format!("task join failed: {}", e));
                                    }
                                }
                            }

                            let db_path_clone = db_path.clone();
                            let run_id_clone = run_id;
                            pending_write = Some(tokio::task::spawn_blocking(move || {
                                write_batch(&db_path_clone, run_id_clone, batch_to_write)
                            }));
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        if let Some(handle) = pending_write.take() {
                            match handle.await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => {
                                    last_error = Some(format!("final batch write failed: {}", e));
                                }
                                Err(e) => {
                                    last_error = Some(format!("task join failed: {}", e));
                                }
                            }
                        }
                        if !batch.is_empty() {
                            let db_path_clone = db_path.clone();
                            let batch_to_write = std::mem::take(&mut batch);
                            let run_id_clone = run_id;
                            let result = tokio::task::spawn_blocking(move || {
                                write_batch(&db_path_clone, run_id_clone, batch_to_write)
                            }).await;
                            if let Err(e) = result {
                                last_error = Some(format!("final batch task join failed: {}", e));
                            }
                        }
                        break;
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(500)) => {
                        if !batch.is_empty() && pending_write.is_none() {
                            let batch_to_write = std::mem::take(&mut batch);
                            let db_path_clone = db_path.clone();
                            let run_id_clone = run_id;
                            pending_write = Some(tokio::task::spawn_blocking(move || {
                                write_batch(&db_path_clone, run_id_clone, batch_to_write)
                            }));
                        }
                    }
                }
            }

            if let Some(err) = last_error {
                eprintln!("db writer error: {}", err);
            }
        });

        Ok(Self {
            sender: result_tx,
            shutdown_tx: Some(shutdown_tx),
            run_id,
        })
    }

    pub fn write(&self, result: ProbeResult) {
        let _ = self.sender.send(result);
    }

    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

#[allow(dead_code)]
fn write_batch(db_path: &Path, run_id: i64, batch: Vec<ProbeResult>) -> Result<()> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut conn = Connection::open(db_path).context("failed to open db for batch write")?;
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;",
    )?;

    let tx = conn.transaction()?;
    for result in &batch {
        let cookies_json = serde_json::to_string(&result.cookies)
            .with_context(|| format!("failed to serialize cookies for {}", result.domain))?;
        let redirect_json = serde_json::to_string(&result.redirect_info).ok();
        let cloud_json = serde_json::to_string(&result.cloud_info).ok();
        let takeover_json = serde_json::to_string(&result.takeover).ok();
        let tls_json = serde_json::to_string(&result.tls_info).ok();
        let timing_json = serde_json::to_string(&result.timing).ok();
        let methods_json = serde_json::to_string(&result.allowed_http_methods).ok();

        tx.execute(
            "INSERT INTO probes (run_id, domain, probe_timestamp, alive, protocol, final_url, status_code, response_time_ms, error, waf_name, favicon_hash, trace_enabled, cookies, redirect_info, cloud_info, takeover, tls_info, timing, allowed_methods)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
            params![
                run_id,
                &result.domain,
                result.probe_timestamp.to_rfc3339(),
                i64::from(result.alive),
                result.protocol.as_deref(),
                result.final_url.as_deref(),
                result.status_code.map(i64::from),
                result.response_time_ms.map(|v| v as i64),
                result.error.as_deref(),
                result.waf.as_ref().and_then(|w| w.name.clone()).as_deref(),
                result.favicon_hash.as_deref(),
                result.trace_enabled.map(|v| i64::from(v)),
                cookies_json,
                redirect_json,
                cloud_json,
                takeover_json,
                tls_json,
                timing_json,
                methods_json,
            ],
        )?;
        for tech in &result.technologies {
            let evidence_json = serde_json::to_string(&tech.evidence)?;
            tx.execute(
                "INSERT INTO technologies (run_id, domain, technology_name, confidence, evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    run_id,
                    &result.domain,
                    &tech.name,
                    i64::from(tech.confidence),
                    evidence_json
                ],
            )?;
        }
        for finding in &result.security_findings {
            tx.execute(
                "INSERT INTO security_findings (run_id, domain, finding_id, category, severity, title, explanation, evidence)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    run_id,
                    &result.domain,
                    &finding.id,
                    &finding.category,
                    finding.severity.as_str(),
                    &finding.title,
                    &finding.explanation,
                    &finding.evidence
                ],
            )?;
        }
    }
    tx.commit()?;
    Ok(())
}

impl RunMetadata {
    pub fn from_config(targets_total: usize, config: &AppConfig) -> Self {
        Self {
            targets_total: targets_total as i64,
            concurrency: config.concurrency as i64,
            timeout_secs: config.timeout_secs as i64,
            retries: config.retries as i64,
            user_agent: config.user_agent.clone(),
            insecure: config.insecure,
        }
    }
}

impl Database {
    pub fn new(path: &Path) -> Result<Self> {
        let conn = Connection::open(path).with_context(|| format!("failed to open {:?}", path))?;
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS analysis_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                targets_total INTEGER NOT NULL,
                targets_processed INTEGER NOT NULL DEFAULT 0,
                concurrency INTEGER NOT NULL,
                timeout_secs INTEGER NOT NULL,
                retries INTEGER NOT NULL,
                user_agent TEXT NOT NULL,
                insecure INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS probes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                probe_timestamp TEXT NOT NULL,
                alive INTEGER NOT NULL,
                protocol TEXT,
                final_url TEXT,
                status_code INTEGER,
                response_time_ms INTEGER,
                error TEXT,
                waf_name TEXT,
                favicon_hash TEXT,
                trace_enabled INTEGER,
                cookies TEXT,
                redirect_info TEXT,
                cloud_info TEXT,
                takeover TEXT,
                tls_info TEXT,
                timing TEXT,
                allowed_methods TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS technologies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                technology_name TEXT NOT NULL,
                confidence INTEGER NOT NULL,
                evidence TEXT,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS security_findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                category TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                explanation TEXT NOT NULL,
                evidence TEXT NOT NULL,
                FOREIGN KEY (run_id) REFERENCES analysis_runs(id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_probes_domain ON probes(domain);
            CREATE INDEX IF NOT EXISTS idx_probes_run ON probes(run_id);
            CREATE INDEX IF NOT EXISTS idx_technologies_run ON technologies(run_id);
            CREATE INDEX IF NOT EXISTS idx_technologies_domain ON technologies(domain);
            CREATE INDEX IF NOT EXISTS idx_security_findings_run ON security_findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_security_findings_domain ON security_findings(domain);",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
            writer: Mutex::new(None),
        })
    }

    #[allow(dead_code)]
    pub fn set_writer(&self, writer: Arc<DbWriter>) {
        let mut w = self.writer.lock().unwrap();
        *w = Some(writer);
    }

    #[allow(dead_code)]
    pub fn get_writer(&self) -> Option<Arc<DbWriter>> {
        let w = self.writer.lock().unwrap();
        w.clone()
    }

    pub fn create_analysis_run(&self, metadata: &RunMetadata) -> Result<i64> {
        let now = Utc::now().to_rfc3339();
        let conn = self.lock()?;
        conn.execute(
            "INSERT INTO analysis_runs (
                started_at, targets_total, targets_processed, concurrency, timeout_secs, retries, user_agent, insecure
            ) VALUES (?1, ?2, 0, ?3, ?4, ?5, ?6, ?7)",
            params![
                now,
                metadata.targets_total,
                metadata.concurrency,
                metadata.timeout_secs,
                metadata.retries,
                &metadata.user_agent,
                i64::from(metadata.insecure),
            ],
        )?;
        Ok(conn.last_insert_rowid())
    }

    pub fn persist_results(&self, run_id: i64, results: &[ProbeResult]) -> Result<()> {
        let mut conn = self.lock()?;
        let tx = conn.transaction()?;
        for result in results {
            let cookies_json = serde_json::to_string(&result.cookies)
                .with_context(|| format!("failed to serialize cookies for {}", result.domain))?;
            let redirect_json = serde_json::to_string(&result.redirect_info).ok();
            let cloud_json = serde_json::to_string(&result.cloud_info).ok();
            let takeover_json = serde_json::to_string(&result.takeover).ok();
            let tls_json = serde_json::to_string(&result.tls_info).ok();
            let timing_json = serde_json::to_string(&result.timing).ok();
            let methods_json = serde_json::to_string(&result.allowed_http_methods).ok();

            tx.execute(
                "INSERT INTO probes (run_id, domain, probe_timestamp, alive, protocol, final_url, status_code, response_time_ms, error, waf_name, favicon_hash, trace_enabled, cookies, redirect_info, cloud_info, takeover, tls_info, timing, allowed_methods)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19)",
                params![
                    run_id,
                    &result.domain,
                    result.probe_timestamp.to_rfc3339(),
                    i64::from(result.alive),
                    result.protocol.as_deref(),
                    result.final_url.as_deref(),
                    result.status_code.map(i64::from),
                    result.response_time_ms.map(|v| v as i64),
                    result.error.as_deref(),
                    result.waf.as_ref().and_then(|w| w.name.clone()).as_deref(),
                    result.favicon_hash.as_deref(),
                    result.trace_enabled.map(|v| i64::from(v)),
                    cookies_json,
                    redirect_json,
                    cloud_json,
                    takeover_json,
                    tls_json,
                    timing_json,
                    methods_json,
                ],
            )?;
            for tech in &result.technologies {
                let evidence_json = serde_json::to_string(&tech.evidence)?;
                tx.execute(
                    "INSERT INTO technologies (run_id, domain, technology_name, confidence, evidence)
                    VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        run_id,
                        &result.domain,
                        &tech.name,
                        i64::from(tech.confidence),
                        evidence_json
                    ],
                )?;
            }
            for finding in &result.security_findings {
                tx.execute(
                    "INSERT INTO security_findings (
                        run_id, domain, finding_id, category, severity, title, explanation, evidence
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        run_id,
                        &result.domain,
                        &finding.id,
                        &finding.category,
                        finding.severity.as_str(),
                        &finding.title,
                        &finding.explanation,
                        &finding.evidence
                    ],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn finalize_analysis_run(&self, run_id: i64, processed: i64) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let conn = self.lock()?;
        conn.execute(
            "UPDATE analysis_runs SET completed_at = ?1, targets_processed = ?2 WHERE id = ?3",
            params![now, processed, run_id],
        )?;
        Ok(())
    }

    fn lock(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| anyhow::anyhow!("db mutex poisoned"))
    }

    #[allow(dead_code)]
    pub fn query(&self, sql: &str) -> Result<Vec<Vec<String>>> {
        let conn = self.lock()?;
        let mut stmt = conn.prepare(sql)?;
        let column_count = stmt.column_count();
        let column_names: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();

        let rows = stmt.query_map([], |row| {
            let mut values = Vec::new();
            for i in 0..column_count {
                let value: String = match row.get_ref(i)? {
                    rusqlite::types::ValueRef::Null => "NULL".to_string(),
                    rusqlite::types::ValueRef::Integer(i) => i.to_string(),
                    rusqlite::types::ValueRef::Real(f) => f.to_string(),
                    rusqlite::types::ValueRef::Text(t) => String::from_utf8_lossy(t).to_string(),
                    rusqlite::types::ValueRef::Blob(b) => format!("[blob {} bytes]", b.len()),
                };
                values.push(value);
            }
            Ok(values)
        })?;

        let mut results = vec![column_names];
        for row in rows {
            results.push(row?);
        }
        Ok(results)
    }

    #[allow(dead_code)]
    pub fn query_domains_with_tech(&self, tech_name: &str) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let mut stmt =
            conn.prepare("SELECT DISTINCT domain FROM technologies WHERE technology_name LIKE ?1")?;
        let domains = stmt.query_map([format!("%{}%", tech_name)], |row| row.get(0))?;
        Ok(domains.filter_map(|d| d.ok()).collect())
    }

    #[allow(dead_code)]
    pub fn query_domains_with_findings(&self, min_severity: &str) -> Result<Vec<String>> {
        let conn = self.lock()?;
        let severity_col = match min_severity {
            "high" => "high",
            "medium" => "medium",
            "low" => "low",
            _ => "low",
        };

        let mut stmt = conn.prepare(&format!(
            "SELECT DISTINCT domain FROM security_findings WHERE severity = '{}'",
            severity_col
        ))?;
        let domains = stmt.query_map([], |row| row.get(0))?;
        Ok(domains.filter_map(|d| d.ok()).collect())
    }

    #[allow(dead_code)]
    pub fn format_query_results(&self, results: &[Vec<String>], sql: &str) -> String {
        if results.is_empty() {
            return "No results".to_string();
        }

        let col_widths: Vec<usize> = (0..results[0].len())
            .map(|col_idx| {
                results
                    .iter()
                    .map(|row| row.get(col_idx).map(|s| s.len()).unwrap_or(0))
                    .max()
                    .unwrap_or(0)
                    .max(results[0][col_idx].len())
            })
            .collect();

        let border = format!(
            "+{}+",
            col_widths
                .iter()
                .map(|w| "-".repeat(*w + 2))
                .collect::<Vec<_>>()
                .join("+")
        );

        let mut output = format!("\n-- Query: {}\n{}\n", sql, border);

        for (row_idx, row) in results.iter().enumerate() {
            if row_idx == 1 {
                output.push_str(&border);
                output.push('\n');
            }
            output.push('|');
            for (i, cell) in row.iter().enumerate() {
                output.push(' ');
                output.push_str(&cell);
                output.push_str(&" ".repeat(col_widths[i] - cell.len()));
                output.push_str(" |");
            }
            output.push('\n');
        }
        output.push_str(&border);
        output
    }
}

#[cfg(test)]
mod tests {
    use super::{Database, RunMetadata};
    use crate::config::AppConfig;
    use crate::probe::map_probe_success;
    use crate::security::{Severity, WafInfo};
    use tempfile::tempdir;

    fn test_config(tmpdir: &tempfile::TempDir) -> AppConfig {
        AppConfig {
            input: std::path::PathBuf::from("t.txt"),
            output: crate::cli::OutputFormat::Terminal,
            output_file: None,
            db: tmpdir.path().join("test.db"),
            concurrency: 50,
            timeout_secs: 10,
            retries: 1,
            user_agent: "test/1.0".to_string(),
            insecure: false,
            ct_logs: false,
            monitor: false,
            interval: 60,
            webhook: None,
            cve_lookup: false,
            fast: false,
            aggressive: false,
        }
    }

    fn sample_result(domain: &str) -> crate::probe::ProbeResult {
        map_probe_success(
            domain,
            "https",
            &format!("https://{}/", domain),
            200,
            30,
            vec![],
            vec![crate::security::SecurityFinding {
                id: "test-finding".to_string(),
                category: "security_headers".to_string(),
                severity: Severity::Medium,
                title: "Test".to_string(),
                explanation: "Test".to_string(),
                evidence: "test".to_string(),
            }],
            Some(WafInfo {
                name: Some("Cloudflare".to_string()),
                blocked: false,
                evidence: "cf-ray".to_string(),
            }),
            None,
            Some(false),
            vec![],
        )
    }

    #[test]
    fn database_creates_tables_on_new() {
        let tmpdir = tempdir().unwrap();
        let db = Database::new(&tmpdir.path().join("new.db")).unwrap();
        let meta = RunMetadata {
            targets_total: 10,
            concurrency: 50,
            timeout_secs: 10,
            retries: 1,
            user_agent: "test".to_string(),
            insecure: false,
        };
        let run_id = db.create_analysis_run(&meta).unwrap();
        assert!(run_id >= 1);
    }

    #[test]
    fn database_persists_and_finalizes() {
        let tmpdir = tempdir().unwrap();
        let db = Database::new(&tmpdir.path().join("test.db")).unwrap();
        let meta = RunMetadata {
            targets_total: 5,
            concurrency: 50,
            timeout_secs: 10,
            retries: 1,
            user_agent: "test".to_string(),
            insecure: false,
        };
        let run_id = db.create_analysis_run(&meta).unwrap();
        let results = vec![
            sample_result("a.com"),
            sample_result("b.com"),
            sample_result("c.com"),
        ];
        db.persist_results(run_id, &results).unwrap();
        db.finalize_analysis_run(run_id, 3).unwrap();
        let conn = db.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT targets_processed FROM analysis_runs WHERE id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 3);
    }

    #[test]
    fn database_persists_technologies_and_findings() {
        let tmpdir = tempdir().unwrap();
        let db = Database::new(&tmpdir.path().join("test2.db")).unwrap();
        let meta = RunMetadata {
            targets_total: 1,
            concurrency: 50,
            timeout_secs: 10,
            retries: 1,
            user_agent: "test".to_string(),
            insecure: false,
        };
        let run_id = db.create_analysis_run(&meta).unwrap();

        let mut result = sample_result("tech.com");
        result
            .technologies
            .push(crate::technology::TechnologyMatch {
                name: "nginx".to_string(),
                confidence: 80,
                evidence: vec!["header:server~nginx".to_string()],
                version: None,
                is_dev_mode: false,
            });

        db.persist_results(run_id, &[result]).unwrap();

        let conn = db.lock().unwrap();
        let tech_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM technologies WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .unwrap();
        let finding_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM security_findings WHERE run_id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tech_count, 1);
        assert_eq!(finding_count, 1);
    }

    #[test]
    fn run_metadata_from_config() {
        let tmpdir = tempdir().unwrap();
        let cfg = test_config(&tmpdir);
        let meta = RunMetadata::from_config(100, &cfg);
        assert_eq!(meta.targets_total, 100);
        assert_eq!(meta.concurrency, 50);
        assert_eq!(meta.timeout_secs, 10);
        assert_eq!(meta.retries, 1);
        assert_eq!(meta.user_agent, "test/1.0");
        assert!(!meta.insecure);
    }

    #[test]
    fn database_handles_empty_results() {
        let tmpdir = tempdir().unwrap();
        let db = Database::new(&tmpdir.path().join("empty.db")).unwrap();
        let meta = RunMetadata {
            targets_total: 3,
            concurrency: 50,
            timeout_secs: 10,
            retries: 1,
            user_agent: "test".to_string(),
            insecure: false,
        };
        let run_id = db.create_analysis_run(&meta).unwrap();
        db.persist_results(run_id, &[]).unwrap();
        db.finalize_analysis_run(run_id, 0).unwrap();
        let conn = db.lock().unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT targets_processed FROM analysis_runs WHERE id = ?1",
                [run_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn database_query_basic() {
        let tmpdir = tempdir().unwrap();
        let db = Database::new(&tmpdir.path().join("query.db")).unwrap();
        let meta = RunMetadata {
            targets_total: 2,
            concurrency: 50,
            timeout_secs: 10,
            retries: 1,
            user_agent: "test".to_string(),
            insecure: false,
        };
        let run_id = db.create_analysis_run(&meta).unwrap();
        db.persist_results(run_id, &[sample_result("example.com")])
            .unwrap();

        let results = db
            .query("SELECT domain, alive FROM probes WHERE run_id = 1")
            .unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0], vec!["domain", "alive"]);
        assert!(results.len() >= 2);
    }

    #[test]
    fn database_query_domains_with_tech() {
        let tmpdir = tempdir().unwrap();
        let db = Database::new(&tmpdir.path().join("tech_query.db")).unwrap();
        let meta = RunMetadata {
            targets_total: 2,
            concurrency: 50,
            timeout_secs: 10,
            retries: 1,
            user_agent: "test".to_string(),
            insecure: false,
        };
        let run_id = db.create_analysis_run(&meta).unwrap();

        let mut result = sample_result("nginx.example.com");
        result
            .technologies
            .push(crate::technology::TechnologyMatch {
                name: "nginx".to_string(),
                confidence: 90,
                evidence: vec![],
                version: None,
                is_dev_mode: false,
            });
        db.persist_results(run_id, &[result]).unwrap();

        let domains = db.query_domains_with_tech("nginx").unwrap();
        assert!(domains.contains(&"nginx.example.com".to_string()));
    }

    #[test]
    fn database_query_domains_with_findings() {
        let tmpdir = tempdir().unwrap();
        let db = Database::new(&tmpdir.path().join("findings_query.db")).unwrap();
        let meta = RunMetadata {
            targets_total: 1,
            concurrency: 50,
            timeout_secs: 10,
            retries: 1,
            user_agent: "test".to_string(),
            insecure: false,
        };
        let run_id = db.create_analysis_run(&meta).unwrap();

        let mut result = sample_result("secure.example.com");
        result
            .security_findings
            .push(crate::security::SecurityFinding {
                id: "test-high".to_string(),
                category: "test".to_string(),
                severity: Severity::High,
                title: "High Severity".to_string(),
                explanation: "desc".to_string(),
                evidence: "ev".to_string(),
            });
        db.persist_results(run_id, &[result]).unwrap();

        let domains = db.query_domains_with_findings("high").unwrap();
        assert!(domains.contains(&"secure.example.com".to_string()));
    }

    #[test]
    fn database_format_query_results() {
        let tmpdir = tempdir().unwrap();
        let db = Database::new(&tmpdir.path().join("format.db")).unwrap();
        let results = vec![
            vec!["name".to_string(), "value".to_string()],
            vec!["test".to_string(), "123".to_string()],
        ];
        let formatted = db.format_query_results(&results, "SELECT * FROM test");
        assert!(formatted.contains("name"));
        assert!(formatted.contains("value"));
        assert!(formatted.contains("test"));
        assert!(formatted.contains("123"));
    }
}
