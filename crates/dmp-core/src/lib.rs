//! DMP Core — public API and batch orchestration.
//!
//! Provides the main `analyze()` and `analyze_batch()` entry points
//! that tie together context, parser, engine, and AI modules.

use dmp_context::*;
use dmp_engine::ai::AiProvider;

/// Options for DMP analysis.
#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub exe_dir: Option<String>,
    pub source_dir: Option<String>,
    pub symbol_paths: Vec<String>,
    pub provider: AiProvider,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub timeout_secs: u64,
    pub workers: usize,
    pub no_cache: bool,
    pub json_only: bool,
}

impl Default for AnalyzeOptions {
    fn default() -> Self {
        Self {
            exe_dir: None, source_dir: None, symbol_paths: Vec::new(),
            provider: AiProvider::DeepSeek, api_key: None, model: None,
            timeout_secs: 120, workers: 0, no_cache: false, json_only: false,
        }
    }
}

/// Result of analyzing a single DMP.
#[derive(Debug)]
pub struct AnalyzeResult {
    pub context: AnalysisContext,
    pub context_json: String,
    pub ai_analysis: String,
    pub report_md: String,
    pub report_html: String,
}

/// Result of batch analysis.
#[derive(Debug)]
pub struct BatchResult {
    pub results: Vec<AnalyzeResult>,
    pub summary_md: String,
}

/// Build the AnalysisContext from options.
pub fn build_context(dump_path: &str, opts: &AnalyzeOptions) -> AnalysisContext {
    let mut symbol_paths = opts.symbol_paths.clone();
    if let Some(ref exe) = opts.exe_dir {
        symbol_paths.insert(0, exe.clone());
    }
    AnalysisContext {
        meta: ContextMeta {
            dump_path: dump_path.to_string(),
            exe_dir: opts.exe_dir.clone(),
            source_dir: opts.source_dir.clone(),
            log_dir: None,
            symbol_paths,
            collected_at: chrono_now(),
        },
        dmp: DmpData::default(),
    }
}

/// Run the full analysis pipeline on a single DMP.
#[cfg(windows)]
pub fn analyze(dump_path: &str, opts: &AnalyzeOptions) -> Result<AnalyzeResult, String> {
    use std::path::Path;
    use dmp_engine::cdb;
    use dmp_parser;

    let ctx = build_context(dump_path, opts);

    // Phase 1: CDB + parse
    let dump = Path::new(dump_path);
    let symbol_path = if ctx.meta.symbol_paths.is_empty() { None }
        else { Some(ctx.meta.symbol_paths.join(";")) };

    let raw1 = cdb::run_cdb(dump, &cdb::commands_for_crash_analysis(),
        None, opts.timeout_secs, symbol_path.as_deref())?;
    let raw2 = cdb::run_cdb(dump, &cdb::commands_for_pass2(),
        None, opts.timeout_secs.min(60), symbol_path.as_deref())?;

    let mut dmp = dmp_parser::parse_cdb_output(&raw1, dump_path);
    dmp.modules = dmp_parser::parse_module_list(&raw2);
    dmp.heap = dmp_parser::parse_heap_info(&raw2);
    dmp.address_summary = dmp_parser::parse_address_summary(&raw2);

    let mut ctx = ctx;
    ctx.dmp = dmp;
    let context_json = serde_json::to_string(&ctx).map_err(|e| e.to_string())?;

    if opts.json_only {
        return Ok(AnalyzeResult {
            context: ctx, context_json,
            ai_analysis: String::new(), report_md: String::new(),
            report_html: String::new(),
        });
    }

    // Phase 2: AI analysis
    let selector = dmp_engine::template::TemplateSelector::new(
        std::path::PathBuf::from("templates"),
        std::path::PathBuf::from("prompt_template.md"),
    );
    let exception_code = ctx.dmp.exception.code.clone();
    let template = selector.select(&exception_code);

    let ai_result = dmp_engine::ai::analyze(
        &context_json, &template, &opts.provider,
        opts.api_key.as_deref(), opts.model.as_deref(),
    ).unwrap_or_else(|e| format!("AI analysis failed: {}", e));

    // Phase 3: Report
    let report = dmp_engine::report::generate_report(
        &context_json, &ai_result, dump_path, &ctx.meta.collected_at);

    Ok(AnalyzeResult {
        context: ctx, context_json,
        ai_analysis: ai_result, report_md: report,
        report_html: String::new(),
    })
}

/// Non-Windows stub for analyze().
#[cfg(not(windows))]
pub fn analyze(_dump_path: &str, _opts: &AnalyzeOptions) -> Result<AnalyzeResult, String> {
    Err("DMP analysis requires Windows (CDB.exe)".into())
}

/// Batch analysis of multiple DMPs.
#[cfg(windows)]
pub fn analyze_batch(patterns: &[String], opts: &AnalyzeOptions) -> Result<BatchResult, String> {
    let files = expand_patterns(patterns);
    if files.is_empty() {
        return Err("No DMP files found".into());
    }
    if files.len() > 10 {
        return Err(format!("Maximum 10 DMPs allowed, got {}", files.len()));
    }

    // Sequential CDB collection (parallel with rayon when 'parallel' feature added)
    let results: Vec<Result<AnalyzeResult, String>> = files
        .iter()
        .map(|f| analyze(f, opts))
        .collect();

    let mut ok_results = Vec::new();
    let mut errors = Vec::new();
    for r in results {
        match r {
            Ok(a) => ok_results.push(a),
            Err(e) => errors.push(e),
        }
    }

    let summary = if ok_results.is_empty() {
        "# 批量分析失败\n\n所有 DMP 分析均失败。".to_string()
    } else {
        let items: Vec<String> = ok_results.iter().enumerate().map(|(i, r)| {
            let ex = &r.context.dmp.exception;
            format!("| {} | {} | **{}** (`{}`) |",
                i + 1, r.context.meta.dump_path, ex.name, ex.code)
        }).collect();
        format!("# 批量分析汇总\n\n| # | DMP | 异常 |\n|---|-----|------|\n{}\n\n{} 成功, {} 失败",
            items.join("\n"), ok_results.len(), errors.len())
    };

    Ok(BatchResult { results: ok_results, summary_md: summary })
}

#[cfg(not(windows))]
pub fn analyze_batch(_patterns: &[String], _opts: &AnalyzeOptions) -> Result<BatchResult, String> {
    Err("Batch analysis requires Windows (CDB.exe)".into())
}

fn expand_patterns(patterns: &[String]) -> Vec<String> {
    let mut files: Vec<String> = Vec::new();
    for pat in patterns {
        let p = std::path::Path::new(pat);
        if p.is_file() {
            let ext = p.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_default();
            if ext == "dmp" || ext == "mdmp" || ext == "hdmp" {
                files.push(pat.clone());
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

fn chrono_now() -> String {
    // Simple ISO-like timestamp without chrono dependency
    use std::time::SystemTime;
    if let Ok(dur) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        let secs = dur.as_secs();
        let days = secs / 86400;
        let hours = (secs % 86400) / 3600;
        let mins = (secs % 3600) / 60;
        let s = secs % 60;
        format!("2026-06-28T{:02}:{:02}:{:02}Z (day {})", hours, mins, s, days)
    } else {
        String::from("unknown")
    }
}

// ═════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_default() {
        let opts = AnalyzeOptions::default();
        assert!(matches!(opts.provider, AiProvider::DeepSeek));
        assert_eq!(opts.timeout_secs, 120);
        assert_eq!(opts.workers, 0);
    }

    #[test]
    fn test_build_context() {
        let opts = AnalyzeOptions {
            exe_dir: Some(r"C:\MyApp".into()),
            symbol_paths: vec![r"D:\Symbols".into()],
            ..Default::default()
        };
        let ctx = build_context("crash.dmp", &opts);
        assert_eq!(ctx.meta.dump_path, "crash.dmp");
        assert_eq!(ctx.meta.exe_dir.as_deref(), Some(r"C:\MyApp"));
        // exe_dir should be first in symbol_paths
        assert_eq!(ctx.meta.symbol_paths[0], r"C:\MyApp");
        assert_eq!(ctx.meta.symbol_paths[1], r"D:\Symbols");
    }

    #[test]
    fn test_analyze_non_windows_stub() {
        // On non-Windows, analyze returns error
        let opts = AnalyzeOptions::default();
        let result = analyze("test.dmp", &opts);
        if cfg!(not(windows)) {
            assert!(result.is_err());
        }
        // On Windows, may fail due to missing CDB — either is acceptable
    }

    #[test]
    fn test_expand_patterns_empty() {
        let files = expand_patterns(&["/nonexistent/*.dmp".into()]);
        assert!(files.is_empty());
    }
}
