//! CDB (Console Debugger) invocation wrapper.
//! Ported from Python mvp/cdb_runner.py.
//! Windows-only — CDB is part of the Windows SDK.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Known CDB installation paths (Windows SDK).
const CDB_SEARCH_PATHS: &[&str] = &[
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x86\cdb.exe",
    r"C:\Debuggers\x64\cdb.exe",
    r"C:\Debuggers\x86\cdb.exe",
];

/// Locate CDB executable.
pub fn find_cdb(explicit_path: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = explicit_path {
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
        return Err(format!("CDB not found at: {}", p.display()));
    }

    // Check env vars
    for var in &["CDB_PATH", "CDB"] {
        if let Ok(val) = std::env::var(var) {
            let p = Path::new(&val);
            if p.is_file() {
                return Ok(p.to_path_buf());
            }
        }
    }

    // Check known install paths
    for pattern in CDB_SEARCH_PATHS {
        if Path::new(pattern).is_file() {
            return Ok(PathBuf::from(pattern));
        }
    }

    // Fallback: check PATH
    if let Ok(paths) = std::env::var("PATH") {
        for dir in paths.split(';') {
            for name in &["cdb.exe", "cdb"] {
                let p = Path::new(dir).join(name);
                if p.is_file() {
                    return Ok(p);
                }
            }
        }
    }

    Err("Cannot find CDB.exe. Install Windows SDK Debugging Tools.".into())
}

/// Run CDB against a dump file and capture all output.
pub fn run_cdb(
    dump_path: &Path,
    commands: &[&str],
    cdb_path: Option<&Path>,
    timeout_secs: u64,
    symbol_path: Option<&str>,
) -> Result<String, String> {
    if !dump_path.is_file() {
        return Err(format!("Dump file not found: {}", dump_path.display()));
    }

    let cdb = find_cdb(cdb_path)?;

    // Build inline command string
    let mut cmd_string = commands.join("; ");
    if !cmd_string.trim_end().ends_with("; q") {
        cmd_string.push_str("; q");
    }

    // Temp files for stdout/stderr
    let tmp_dir = std::env::temp_dir();
    let out_path = tmp_dir.join(format!("cdb_out_{}.txt", std::process::id()));
    let err_path = tmp_dir.join(format!("cdb_err_{}.txt", std::process::id()));

    let mut cmd = Command::new(&cdb);
    cmd.args(["-z", &dump_path.to_string_lossy()])
       .args(["-c", &cmd_string])
       .args(["-lines", "-noshell"])
       .stdout(std::fs::File::create(&out_path).map_err(|e| format!("Cannot create temp: {}", e))?)
       .stderr(std::fs::File::create(&err_path).map_err(|e| format!("Cannot create temp: {}", e))?);

    // Set symbol path
    if let Some(sp) = symbol_path {
        cmd.env("_NT_SYMBOL_PATH", sp);
    } else if std::env::var("_NT_SYMBOL_PATH").is_err() {
        cmd.env("_NT_SYMBOL_PATH", "");
    }

    let output = cmd.output().map_err(|e| format!("CDB spawn failed: {}", e))?;

    let out_text = std::fs::read_to_string(&out_path)
        .unwrap_or_default();
    let err_text = std::fs::read_to_string(&err_path)
        .unwrap_or_default();

    // Cleanup
    let _ = std::fs::remove_file(&out_path);
    let _ = std::fs::remove_file(&err_path);

    let mut result = out_text;
    if !err_text.trim().is_empty() {
        result.push_str("\n[CDB STDERR]\n");
        result.push_str(&err_text);
    }

    let _ = timeout_secs; // timeout handled by caller with threads
    let _ = output;

    Ok(result)
}

/// Pre-built CDB command sets.
pub fn commands_for_system_info() -> Vec<&'static str> {
    vec!["vertarget", "!sysinfo smbios", "!cpuinfo", "!vm", "!memusage", "!envvar", ".time"]
}

pub fn commands_for_crash_analysis() -> Vec<&'static str> {
    vec![".ecxr", "k 30", "~* k", "vertarget", "!analyze -v"]
}

pub fn commands_for_pass2() -> Vec<&'static str> {
    vec![".reload", "lm", "!heap -s", "!locks", "!address -summary"]
}

// ═════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_cdb_known_paths() {
        // Should find CDB on a system with Windows SDK
        let result = find_cdb(None);
        // May succeed or fail depending on system — don't assert success
        match result {
            Ok(path) => assert!(path.to_string_lossy().contains("cdb")),
            Err(_) => {} // CDB not installed — acceptable
        }
    }

    #[test]
    fn test_find_cdb_explicit_missing() {
        let result = find_cdb(Some(Path::new("/nonexistent/cdb.exe")));
        assert!(result.is_err());
    }

    #[test]
    fn test_commands_not_empty() {
        assert!(!commands_for_crash_analysis().is_empty());
        assert!(!commands_for_pass2().is_empty());
        assert!(commands_for_crash_analysis().contains(&"!analyze -v"));
    }

    #[test]
    fn test_run_cdb_missing_dump() {
        let result = run_cdb(Path::new("/nonexistent.dmp"), &["k"], None, 10, None);
        assert!(result.is_err());
    }
}
