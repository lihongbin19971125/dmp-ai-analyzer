//! End-to-end integration tests using real DMP files.
//!
//! Set env vars to point to test DMPs:
//!   set DMP_TEST_FILE_1=D:\path\to\crash1.dmp
//!   set DMP_TEST_FILE_2=D:\path\to\crash2.dmp
//!
//! Then: cargo test -p dmp-core --test real_dmp_tests -- --test-threads=1

use dmp_core::*;
use dmp_engine::cdb;
use std::path::Path;

fn dmp1() -> String { std::env::var("DMP_TEST_FILE_1").unwrap_or_default() }
fn dmp2() -> String { std::env::var("DMP_TEST_FILE_2").unwrap_or_default() }
fn skip_no_dmp(path: &str) -> bool {
    if path.is_empty() || !Path::new(path).is_file() {
        eprintln!("Skipping: DMP not found (set DMP_TEST_FILE_1 / DMP_TEST_FILE_2)");
        true
    } else { false }
}

// ═══════════════════════════════════════════════════════════════
// Phase 1: CDB invocation tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_cdb_found_on_system() {
    match cdb::find_cdb(None) {
        Ok(path) => assert!(path.to_string_lossy().contains("cdb")),
        Err(e) => panic!("CDB not found: {}", e),
    }
}

#[test]
fn test_run_cdb_pass1_on_real_dmp() {
    let path = dmp1();
    if skip_no_dmp(&path) { return; }

    let output = cdb::run_cdb(
        Path::new(&path), &cdb::commands_for_crash_analysis(), None, 120, None,
    ).expect("CDB pass 1 should succeed");

    assert!(!output.is_empty());
    assert!(output.contains("Access violation") || output.contains("c0000005"));
    assert!(output.contains("App"));
}

#[test]
fn test_run_cdb_pass2_on_real_dmp() {
    let path = dmp1();
    if skip_no_dmp(&path) { return; }

    let output = cdb::run_cdb(
        Path::new(&path), &cdb::commands_for_pass2(), None, 60, None,
    ).expect("CDB pass 2 should succeed");

    assert!(!output.is_empty());
    assert!(output.contains("Reload") || output.contains("Module") || output.contains("start"));
}

// ═══════════════════════════════════════════════════════════════
// Phase 2: Full pipeline
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_analyze_json_only_real_dmp() {
    let path = dmp1();
    if skip_no_dmp(&path) { return; }

    let opts = AnalyzeOptions { json_only: true, timeout_secs: 120, ..Default::default() };
    let result = dmp_core::analyze(&path, &opts).expect("analyze() should succeed");

    assert!(!result.context_json.is_empty());
    let ctx: serde_json::Value = serde_json::from_str(&result.context_json).unwrap();

    let ex = &ctx["dmp"]["exception"];
    let code = ex["code"].as_str().unwrap_or("");
    assert!(code.contains("C0000005") || code.contains("c0000005"));

    let sys = &ctx["dmp"]["system_info"];
    assert!(sys["os_name"].as_str().unwrap_or("").contains("Windows"));
    assert!(sys["cpu_count"].as_u64().unwrap_or(0) > 0);

    let frames = ctx["dmp"]["crash_callstack"].as_array().unwrap();
    assert!(!frames.is_empty());
    assert!(!frames[0]["function"].as_str().unwrap_or("").is_empty());

    let raw = ctx["dmp"]["raw_analyze_output"].as_str().unwrap_or("");
    assert!(!raw.is_empty());
}

#[test]
fn test_analyze_real_dmp_has_registers() {
    let path = dmp1();
    if skip_no_dmp(&path) { return; }

    let opts = AnalyzeOptions { json_only: true, timeout_secs: 120, ..Default::default() };
    let result = dmp_core::analyze(&path, &opts).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&result.context_json).unwrap();
    let regs = &ctx["dmp"]["registers"];
    assert!(!regs.is_null());
    let has = regs["eip"].is_string() || regs["eax"].is_string()
           || regs["rip"].is_string() || regs["rax"].is_string();
    assert!(has, "Should have registers. Got: {:?}", regs);
}

#[test]
fn test_analyze_real_dmp_has_modules() {
    let path = dmp1();
    if skip_no_dmp(&path) { return; }

    let opts = AnalyzeOptions { json_only: true, timeout_secs: 120, ..Default::default() };
    let result = dmp_core::analyze(&path, &opts).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&result.context_json).unwrap();
    let mods = ctx["dmp"]["modules"].as_array().unwrap();
    assert!(!mods.is_empty());
    let has_app = mods.iter().any(|m| {
        m["name"].as_str().unwrap_or("").contains("App")
        || m["path"].as_str().unwrap_or("").contains("App")
    });
    assert!(has_app);
}

// ═══════════════════════════════════════════════════════════════
// Phase 3: Batch analysis
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_analyze_batch_two_dmps() {
    let p1 = dmp1();
    let p2 = dmp2();
    if skip_no_dmp(&p1) || skip_no_dmp(&p2) { return; }

    let opts = AnalyzeOptions { json_only: true, timeout_secs: 120, ..Default::default() };
    let batch = dmp_core::analyze_batch(&[p1, p2], &opts).expect("Batch should succeed");

    assert_eq!(batch.results.len(), 2);
    assert!(!batch.summary_md.is_empty());
    assert!(batch.summary_md.contains("批量分析") || batch.summary_md.contains("汇总"));
}

// ═══════════════════════════════════════════════════════════════
// Phase 4: Report generation
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_generate_report_from_real_dmp() {
    let path = dmp1();
    if skip_no_dmp(&path) { return; }

    let opts = AnalyzeOptions { json_only: true, timeout_secs: 120, ..Default::default() };
    let result = dmp_core::analyze(&path, &opts).unwrap();

    let report = dmp_engine::report::generate_report(
        &result.context_json, "_AI analysis pending_", &path, "2026-06-28T01:37:54Z",
    );

    assert!(report.contains("DMP 崩溃分析报告"));
    assert!(report.contains("C0000005") || report.contains("c0000005"));
    assert!(report.contains("AI 分析"));
    assert!(report.lines().count() > 10);
}

// ═══════════════════════════════════════════════════════════════
// Phase 5: JSON shape validation
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_output_matches_python_baseline_shape() {
    let path = dmp1();
    if skip_no_dmp(&path) { return; }

    let opts = AnalyzeOptions { json_only: true, timeout_secs: 120, ..Default::default() };
    let result = dmp_core::analyze(&path, &opts).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&result.context_json).unwrap();
    let dmp = &ctx["dmp"];

    for key in ["system_info", "metadata", "exception", "crash_callstack",
                "all_callstacks", "registers", "modules", "locks", "heap",
                "address_summary", "memory_findings", "raw_analyze_output"] {
        assert!(dmp.get(key).is_some(), "Missing key: {}", key);
    }

    assert!(dmp["system_info"]["os_name"].is_string());
    assert!(dmp["system_info"]["platform"].is_string());
    assert!(dmp["exception"]["code"].is_string());
    assert!(dmp["exception"]["name"].is_string());
}
