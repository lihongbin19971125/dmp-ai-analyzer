//! End-to-end integration tests using real DMP files.
//!
//! These tests require:
//! - CDB (Windows SDK Debugging Tools) installed
//! - Real .dmp files at the paths specified in DMP_PATH_1 / DMP_PATH_2
//!
//! Run with: cargo test -p dmp-core --test real_dmp_tests -- --ignored
//! Or: cargo test -p dmp-core --test real_dmp_tests -- --test-threads=1

use dmp_core::*;
use dmp_engine::cdb;
use std::path::Path;

/// Path to the first real DMP file (Access Violation, null pointer write).
const DMP_PATH_1: &str = r"D:\code\CrashDumpDemo\App\CrashDump_20260628_013754.dmp";

/// Path to the second real DMP file (same app, different crash).
const DMP_PATH_2: &str = r"D:\code\CrashDumpDemo\App\CrashDump_20260628_021419.dmp";

// ═══════════════════════════════════════════════════════════════
// Phase 1: CDB invocation tests
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_cdb_found_on_system() {
    match cdb::find_cdb(None) {
        Ok(path) => {
            assert!(path.to_string_lossy().contains("cdb"),
                "CDB path should contain 'cdb': {}", path.display());
        }
        Err(e) => panic!("CDB not found — required for e2e tests: {}", e),
    }
}

#[test]
fn test_run_cdb_pass1_on_real_dmp() {
    let dmp = Path::new(DMP_PATH_1);
    if !dmp.is_file() {
        eprintln!("Skipping: DMP not found at {}", DMP_PATH_1);
        return;
    }

    let output = cdb::run_cdb(
        dmp,
        &cdb::commands_for_crash_analysis(),
        None,
        120,
        None,
    ).expect("CDB pass 1 should succeed");

    // Verify key output markers
    assert!(!output.is_empty(), "CDB output should not be empty");
    assert!(output.contains("Access violation") || output.contains("c0000005"),
        "Should contain access violation info");
    assert!(output.contains("App"), "Should contain executable name");
    assert!(output.contains("!analyze -v"), "Should contain analysis output");
}

#[test]
fn test_run_cdb_pass2_on_real_dmp() {
    let dmp = Path::new(DMP_PATH_1);
    if !dmp.is_file() {
        eprintln!("Skipping: DMP not found at {}", DMP_PATH_1);
        return;
    }

    let output = cdb::run_cdb(
        dmp,
        &cdb::commands_for_pass2(),
        None,
        60,
        None,
    ).expect("CDB pass 2 should succeed");

    // Pass 2 should have module list or heap info
    assert!(!output.is_empty(), "Pass 2 output should not be empty");
    // At minimum, should contain reload output
    assert!(output.contains("Reload") || output.contains("Module") || output.contains("start"),
        "Pass 2 should contain module/load info");
}

// ═══════════════════════════════════════════════════════════════
// Phase 2: Full pipeline — analyze() with json_only
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_analyze_json_only_real_dmp() {
    let dmp_path = DMP_PATH_1;
    if !Path::new(dmp_path).is_file() {
        eprintln!("Skipping: DMP not found at {}", dmp_path);
        return;
    }

    let opts = AnalyzeOptions {
        json_only: true,
        timeout_secs: 120,
        ..Default::default()
    };

    let result = dmp_core::analyze(dmp_path, &opts)
        .expect("analyze() should succeed for real DMP");

    assert!(result.ai_analysis.is_empty(), "json_only should skip AI");
    assert!(!result.context_json.is_empty(), "context_json should not be empty");

    // Parse JSON and verify structure
    let ctx: serde_json::Value = serde_json::from_str(&result.context_json)
        .expect("context_json should be valid JSON");

    // Top-level dmp key
    let dmp = &ctx["dmp"];
    assert!(!dmp.is_null(), "Should have 'dmp' key in output");

    // Exception info
    let ex = &dmp["exception"];
    assert!(!ex.is_null(), "Should have exception info");
    let code = ex["code"].as_str().unwrap_or("");
    assert!(!code.is_empty(), "Exception code should not be empty");
    // Known: this DMP has access violation
    assert!(code.contains("C0000005") || code.contains("c0000005"),
        "Expected C0000005, got: {}", code);

    // System info
    let sys = &dmp["system_info"];
    assert!(!sys.is_null(), "Should have system_info");
    let os = sys["os_name"].as_str().unwrap_or("");
    assert!(!os.is_empty(), "OS name should not be empty");
    assert!(os.contains("Windows"), "OS should be Windows, got: {}", os);

    let cpu = sys["cpu_count"].as_u64().unwrap_or(0);
    assert!(cpu > 0, "CPU count should be > 0, got: {}", cpu);

    // Callstack
    let cs = dmp["crash_callstack"].as_array();
    assert!(cs.is_some(), "Should have crash_callstack array");
    let frames = cs.unwrap();
    assert!(!frames.is_empty(), "Should have at least 1 callstack frame");

    // First frame should contain App (the crashing executable)
    let first_frame_fn = frames[0]["function"].as_str().unwrap_or("");
    assert!(!first_frame_fn.is_empty(), "First frame should have function name");

    // Raw output preserved
    let raw = dmp["raw_analyze_output"].as_str().unwrap_or("");
    assert!(!raw.is_empty(), "raw_analyze_output should not be empty");
    assert!(raw.contains("Access violation") || raw.contains(".ecxr"),
        "Raw output should contain crash info");
}

#[test]
fn test_analyze_real_dmp_has_registers() {
    let dmp_path = DMP_PATH_1;
    if !Path::new(dmp_path).is_file() {
        return;
    }

    let opts = AnalyzeOptions {
        json_only: true,
        timeout_secs: 120,
        ..Default::default()
    };

    let result = dmp_core::analyze(dmp_path, &opts).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&result.context_json).unwrap();

    let regs = &ctx["dmp"]["registers"];
    assert!(!regs.is_null(), "Should have registers");

    // x86 DMP should have eip/eax/ebx etc.
    let has_x86 = regs["eip"].is_string() || regs["eax"].is_string();
    let has_x64 = regs["rip"].is_string() || regs["rax"].is_string();
    assert!(has_x86 || has_x64, "Should have either x86 or x64 registers. Got: {:?}", regs);
}

#[test]
fn test_analyze_real_dmp_has_modules() {
    let dmp_path = DMP_PATH_1;
    if !Path::new(dmp_path).is_file() {
        return;
    }

    let opts = AnalyzeOptions {
        json_only: true,
        timeout_secs: 120,
        ..Default::default()
    };

    let result = dmp_core::analyze(dmp_path, &opts).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&result.context_json).unwrap();

    let modules = ctx["dmp"]["modules"].as_array();
    assert!(modules.is_some(), "Should have modules array");
    let mods = modules.unwrap();
    assert!(!mods.is_empty(), "Should have at least 1 module");

    // App.exe should be among the modules
    let has_app = mods.iter().any(|m| {
        m["name"].as_str().unwrap_or("").contains("App")
            || m["path"].as_str().unwrap_or("").contains("App")
    });
    assert!(has_app, "Should find App among loaded modules");
}

// ═══════════════════════════════════════════════════════════════
// Phase 3: Batch analysis
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_analyze_batch_two_dmps() {
    let dmp1 = DMP_PATH_1;
    let dmp2 = DMP_PATH_2;

    if !Path::new(dmp1).is_file() || !Path::new(dmp2).is_file() {
        eprintln!("Skipping: one or both DMPs not found");
        return;
    }

    let opts = AnalyzeOptions {
        json_only: true,
        timeout_secs: 120,
        ..Default::default()
    };

    let patterns = vec![dmp1.to_string(), dmp2.to_string()];
    let batch = dmp_core::analyze_batch(&patterns, &opts)
        .expect("Batch analysis should succeed");

    assert_eq!(batch.results.len(), 2, "Should have 2 results");
    assert!(!batch.summary_md.is_empty(), "Should have summary");

    // Both should have context_json
    for (i, r) in batch.results.iter().enumerate() {
        assert!(!r.context_json.is_empty(), "Result {} context_json should not be empty", i);
    }

    // Summary should reference both exceptions
    assert!(batch.summary_md.contains("批量分析") || batch.summary_md.contains("汇总"),
        "Summary should have batch title");
}

// ═══════════════════════════════════════════════════════════════
// Phase 4: Report generation from real DMP
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_generate_report_from_real_dmp() {
    let dmp_path = DMP_PATH_1;
    if !Path::new(dmp_path).is_file() {
        return;
    }

    let opts = AnalyzeOptions {
        json_only: true,
        timeout_secs: 120,
        ..Default::default()
    };

    let result = dmp_core::analyze(dmp_path, &opts).unwrap();

    // Generate report with mock AI analysis (since we used json_only)
    let report = dmp_engine::report::generate_report(
        &result.context_json,
        "_AI analysis pending_",
        dmp_path,
        "2026-06-28T01:37:54Z",
    );

    // Report structure
    assert!(report.contains("DMP 崩溃分析报告"), "Should have report title");
    assert!(report.contains("D:\\code\\CrashDumpDemo"), "Should contain DMP path");
    assert!(report.contains("C0000005") || report.contains("c0000005"),
        "Should contain exception code");
    assert!(report.contains("AI 分析"), "Should have AI section");

    // Report should be valid Markdown
    assert!(report.lines().count() > 10, "Report should have multiple lines");
}

// ═══════════════════════════════════════════════════════════════
// Phase 5: Compare Rust output with Python baseline
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_output_matches_python_baseline_shape() {
    let dmp_path = DMP_PATH_1;
    if !Path::new(dmp_path).is_file() {
        return;
    }

    let opts = AnalyzeOptions {
        json_only: true,
        timeout_secs: 120,
        ..Default::default()
    };

    let result = dmp_core::analyze(dmp_path, &opts).unwrap();
    let ctx: serde_json::Value = serde_json::from_str(&result.context_json).unwrap();
    let dmp = &ctx["dmp"];

    // Verify JSON shape matches Python AnalysisContext.to_dict()
    // All these keys must be present (from Python context.py)
    let required_keys = [
        "system_info", "metadata", "exception", "crash_callstack",
        "all_callstacks", "registers", "modules", "locks", "heap",
        "address_summary", "memory_findings", "raw_analyze_output",
    ];

    for key in &required_keys {
        assert!(dmp.get(key).is_some(), "Missing required key in output: {}", key);
    }

    // system_info must have os_name, platform, cpu_count
    let si = &dmp["system_info"];
    assert!(si["os_name"].is_string());
    assert!(si["platform"].is_string());
    assert!(si["cpu_count"].is_number());

    // exception must have code, name, address
    let ex = &dmp["exception"];
    assert!(ex["code"].is_string());
    assert!(ex["name"].is_string());
    assert!(ex["address"].is_string());
}
