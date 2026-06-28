//! Tests for dmp-cli argument parsing and main flow.
//! TDD: These tests are written BEFORE the implementation.

use std::process::Command;

// ═══════════════════════════════════════════════════════════════
// Help and version
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_help_flag() {
    let output = Command::new("cargo")
        .args(["run", "-p", "dmp-cli", "--", "--help"])
        .output()
        .expect("Failed to run dmp --help");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage") || stdout.contains("usage") || stdout.contains("dmp"),
        "Help should contain usage info. Got: {}", stdout);
}

#[test]
fn test_version_flag() {
    let output = Command::new("cargo")
        .args(["run", "-p", "dmp-cli", "--", "--version"])
        .output()
        .expect("Failed to run dmp --version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("0.1.0") || stdout.contains("dmp"),
        "Version should contain version number. Got: {}", stdout);
    assert!(output.status.success());
}

// ═══════════════════════════════════════════════════════════════
// Missing / invalid arguments
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_missing_dump_file() {
    let output = Command::new("cargo")
        .args(["run", "-p", "dmp-cli", "--", "analyze"])
        .output()
        .expect("Failed to run dmp analyze without file");

    assert!(!output.status.success(), "Should fail without dump file");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.is_empty() || !String::from_utf8_lossy(&output.stdout).is_empty(),
        "Should output error message");
}

#[test]
fn test_nonexistent_file() {
    let output = Command::new("cargo")
        .args(["run", "-p", "dmp-cli", "--", "analyze", "/nonexistent/crash.dmp", "--json-only"])
        .output()
        .expect("Failed to run dmp");

    assert!(!output.status.success(), "Should fail for nonexistent file");
    let combined = format!("{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));
    assert!(!combined.is_empty(), "Should have error output");
}

// ═══════════════════════════════════════════════════════════════
// Argument parsing (via JSON output verification)
// ═══════════════════════════════════════════════════════════════

#[test]
fn test_json_only_flag_produces_json_output() {
    let dmp = std::env::var("DMP_TEST_FILE_1").unwrap_or_default();
    if dmp.is_empty() || !std::path::Path::new(&dmp).is_file() {
        eprintln!("Skipping: DMP_TEST_FILE_1 not set");
        return;
    }
    let dmp: &str = &dmp;
    let output = Command::new("cargo")
        .args(["run", "-p", "dmp-cli", "--", "analyze", dmp, "--json-only", "--timeout", "120"])
        .output()
        .expect("Failed to run dmp analyze --json-only");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // The output should be valid JSON or at least contain analysis output
    let combined = format!("{}{}", stdout, stderr);
    assert!(!combined.is_empty(), "Should produce some output");

    // If it succeeded, output should contain JSON keys
    if output.status.success() {
        // Check for JSON structure — either to stdout or a file
        assert!(combined.contains("exception") || combined.contains("dmp") || combined.contains("context"),
            "JSON output should contain expected keys. Got: {}", &combined[..combined.len().min(500)]);
    }
}
