//! Data model for DMP crash dump analysis.
//!
//! All structs implement `Serialize` for JSON output, matching
//! the Python `AnalysisContext.to_dict()` format exactly.

use serde::{Deserialize, Serialize};

// ── SystemInfo ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SystemInfo {
    pub os_name: String,
    pub os_version: String,
    pub os_build: String,
    pub platform: String,
    pub cpu_count: u32,
    pub cpu_model: String,
    pub cpu_features: Vec<String>,
    pub total_physical_mb: u32,
    pub available_physical_mb: u32,
    pub total_virtual_mb: u32,
    pub total_pagefile_mb: u32,
    pub process_working_set_mb: u32,
    pub process_pagefile_mb: u32,
    pub system_uptime_seconds: u64,
    pub boot_time: Option<String>,
    pub machine_name: Option<String>,
    pub environment: std::collections::HashMap<String, String>,
    pub memory_pressure_reason: Option<String>,
}

impl Default for SystemInfo {
    fn default() -> Self {
        Self {
            os_name: String::new(), os_version: String::new(),
            os_build: String::new(), platform: String::new(),
            cpu_count: 0, cpu_model: String::new(),
            cpu_features: Vec::new(),
            total_physical_mb: 0, available_physical_mb: 0,
            total_virtual_mb: 0, total_pagefile_mb: 0,
            process_working_set_mb: 0, process_pagefile_mb: 0,
            system_uptime_seconds: 0,
            boot_time: None, machine_name: None,
            environment: std::collections::HashMap::new(),
            memory_pressure_reason: None,
        }
    }
}

// ── DmpMetadata ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DmpMetadata {
    pub dump_type: String,
    pub timestamp: String,
    pub os_version: String,
    pub process_name: String,
    pub process_id: u32,
}

impl Default for DmpMetadata {
    fn default() -> Self {
        Self { dump_type: String::new(), timestamp: String::new(),
               os_version: String::new(), process_name: String::new(),
               process_id: 0 }
    }
}

// ── ExceptionInfo ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExceptionInfo {
    pub code: String,
    pub name: String,
    pub address: String,
    #[serde(rename = "type")]
    pub access_type: String,
    pub attempted_address: String,
    pub first_chance: bool,
    pub in_page_error: bool,
    pub security_violation: bool,
}

impl Default for ExceptionInfo {
    fn default() -> Self {
        Self { code: String::new(), name: String::new(),
               address: String::new(), access_type: String::new(),
               attempted_address: String::new(),
               first_chance: true, in_page_error: false,
               security_violation: false }
    }
}

// ── Frame ─────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Frame {
    pub frame_index: u32,
    pub module: String,
    pub function: String,
    pub offset: String,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}

impl Default for Frame {
    fn default() -> Self {
        Self { frame_index: 0, module: String::new(),
               function: String::new(), offset: String::new(),
               source_file: None, source_line: None }
    }
}

// ── ThreadStack ───────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreadStack {
    pub thread_id: u32,
    pub state: String,
    pub callstack: Vec<Frame>,
}

impl Default for ThreadStack {
    fn default() -> Self {
        Self { thread_id: 0, state: String::new(), callstack: Vec::new() }
    }
}

// ── ModuleInfo ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base_address: String,
    pub size: u64,
    pub version: Option<String>,
    pub timestamp: Option<String>,
    pub has_symbols: bool,
}

impl Default for ModuleInfo {
    fn default() -> Self {
        Self { name: String::new(), path: String::new(),
               base_address: String::new(), size: 0,
               version: None, timestamp: None, has_symbols: false }
    }
}

// ── LockInfo ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LockInfo {
    pub lock_type: String,
    pub address: String,
    pub owner_thread: u32,
    pub waiter_count: u32,
}

impl Default for LockInfo {
    fn default() -> Self {
        Self { lock_type: String::new(), address: String::new(),
               owner_thread: 0, waiter_count: 0 }
    }
}

// ── HeapInfo ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HeapInfo {
    pub total_committed_mb: u32,
    pub total_reserved_mb: u32,
    pub free_bytes: u64,
    pub segment_count: u32,
    pub heap_count: u32,
    pub lfh_enabled: bool,
    pub corrupted: bool,
    pub details: Vec<String>,
    pub per_heap_breakdown: Vec<PerHeapInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PerHeapInfo {
    pub address: String,
    pub commit_mb: u32,
    pub reserve_mb: u32,
    pub free_bytes: u64,
    pub segments: u32,
}

impl Default for HeapInfo {
    fn default() -> Self {
        Self { total_committed_mb: 0, total_reserved_mb: 0,
               free_bytes: 0, segment_count: 0, heap_count: 0,
               lfh_enabled: false, corrupted: false,
               details: Vec::new(), per_heap_breakdown: Vec::new() }
    }
}

// ── DmpData ───────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DmpData {
    pub system_info: SystemInfo,
    pub metadata: DmpMetadata,
    pub exception: ExceptionInfo,
    pub crash_callstack: Vec<Frame>,
    pub all_callstacks: Vec<ThreadStack>,
    pub registers: std::collections::HashMap<String, String>,
    pub modules: Vec<ModuleInfo>,
    pub locks: Vec<LockInfo>,
    pub heap: HeapInfo,
    pub address_summary: std::collections::HashMap<String, u64>,
    pub memory_findings: Vec<MemoryFinding>,
    pub raw_analyze_output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MemoryFinding {
    pub indicator: String,
    pub severity: String,
    pub evidence: String,
    pub recommendation: String,
}

impl Default for DmpData {
    fn default() -> Self {
        Self { system_info: SystemInfo::default(),
               metadata: DmpMetadata::default(),
               exception: ExceptionInfo::default(),
               crash_callstack: Vec::new(), all_callstacks: Vec::new(),
               registers: std::collections::HashMap::new(),
               modules: Vec::new(), locks: Vec::new(),
               heap: HeapInfo::default(),
               address_summary: std::collections::HashMap::new(),
               memory_findings: Vec::new(),
               raw_analyze_output: String::new() }
    }
}

// ── AnalysisContext ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AnalysisContext {
    #[serde(flatten)]
    pub meta: ContextMeta,
    pub dmp: DmpData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextMeta {
    pub dump_path: String,
    pub exe_dir: Option<String>,
    pub source_dir: Option<String>,
    pub log_dir: Option<String>,
    pub symbol_paths: Vec<String>,
    pub collected_at: String,
}

impl Default for AnalysisContext {
    fn default() -> Self {
        Self { meta: ContextMeta::default(), dmp: DmpData::default() }
    }
}

impl Default for ContextMeta {
    fn default() -> Self {
        Self { dump_path: String::new(), exe_dir: None,
               source_dir: None, log_dir: None,
               symbol_paths: Vec::new(), collected_at: String::new() }
    }
}

// ── API Types ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum AiProvider { DeepSeek, OpenAI, Anthropic }

#[derive(Debug, Clone)]
pub struct AnalyzeOptions {
    pub exe_dir: Option<String>,
    pub source_dir: Option<String>,
    pub log_dir: Option<String>,
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
        Self { exe_dir: None, source_dir: None, log_dir: None,
               symbol_paths: Vec::new(), provider: AiProvider::DeepSeek,
               api_key: None, model: None, timeout_secs: 120,
               workers: 0, no_cache: false, json_only: false }
    }
}

#[derive(Debug, Clone)]
pub struct AnalyzeResult {
    pub context: AnalysisContext,
    pub context_json: String,
    pub ai_analysis: String,
    pub report_md: String,
    pub report_html: String,
}

#[derive(Debug, Clone)]
pub struct BatchResult {
    pub results: Vec<AnalyzeResult>,
    pub summary_md: String,
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_system_info_json() {
        let si = SystemInfo {
            os_name: "Windows 11".into(),
            os_version: "10.0.26100".into(),
            platform: "x64".into(),
            cpu_count: 20,
            cpu_model: "Intel Core i7-13700".into(),
            total_physical_mb: 32768,
            available_physical_mb: 2048,
            system_uptime_seconds: 259200,
            memory_pressure_reason: Some("内存不足".into()),
            ..Default::default()
        };
        let json = serde_json::to_string(&si).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["os_name"], "Windows 11");
        assert_eq!(parsed["cpu_count"], 20);
        assert_eq!(parsed["memory_pressure_reason"], "内存不足");
    }

    #[test]
    fn test_exception_info_serialize_type_field() {
        let ei = ExceptionInfo {
            code: "C0000005".into(),
            name: "ACCESS_VIOLATION".into(),
            address: "00007FF8ABCD1234".into(),
            access_type: "read".into(),
            attempted_address: "0000000000000000".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&ei).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Python uses "type" as key (serde rename)
        assert_eq!(parsed["type"], "read");
        assert_eq!(parsed["code"], "C0000005");
    }

    #[test]
    fn test_frame_with_source() {
        let f = Frame {
            frame_index: 0, module: "myapp.exe".into(),
            function: "myapp!ProcessData+0x42".into(),
            offset: "+0x42".into(),
            source_file: Some("process.cpp".into()),
            source_line: Some(342),
        };
        let json = serde_json::to_string(&f).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["source_file"], "process.cpp");
        assert_eq!(parsed["source_line"], 342);
    }

    #[test]
    fn test_frame_no_source_is_null() {
        let f = Frame {
            frame_index: 1, module: "ntdll.dll".into(),
            function: "ntdll!RtlUserThreadStart+0x21".into(),
            ..Default::default()
        };
        let json = serde_json::to_string(&f).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["source_file"].is_null());
    }

    #[test]
    fn test_heap_info_with_per_heap() {
        let h = HeapInfo {
            total_committed_mb: 512, total_reserved_mb: 1024,
            free_bytes: 64_000_000, segment_count: 8, heap_count: 3,
            lfh_enabled: true,
            per_heap_breakdown: vec![PerHeapInfo {
                address: "0000012340000000".into(),
                commit_mb: 200, reserve_mb: 400,
                free_bytes: 30_000_000, segments: 2,
            }],
            ..Default::default()
        };
        let json = serde_json::to_string(&h).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["heap_count"], 3);
        assert_eq!(parsed["lfh_enabled"], true);
        assert_eq!(parsed["per_heap_breakdown"][0]["address"], "0000012340000000");
    }

    #[test]
    fn test_dmp_data_all_keys_present() {
        let d = DmpData::default();
        let json = serde_json::to_string(&d).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        for key in ["system_info", "metadata", "exception", "crash_callstack",
                    "all_callstacks", "registers", "modules", "locks", "heap",
                    "address_summary", "memory_findings", "raw_analyze_output"] {
            assert!(parsed.get(key).is_some(), "Missing key: {}", key);
        }
    }

    #[test]
    fn test_memory_finding_json() {
        let mf = MemoryFinding {
            indicator: "high_commit".into(),
            severity: "high".into(),
            evidence: "堆平均提交 120MB".into(),
            recommendation: "检查是否存在内存泄漏".into(),
        };
        let json = serde_json::to_string(&mf).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["severity"], "high");
    }

    #[test]
    fn test_context_json_matches_python_shape() {
        let ctx = AnalysisContext {
            meta: ContextMeta {
                dump_path: r"C:\dumps\crash.dmp".into(),
                exe_dir: Some(r"C:\MyApp".into()),
                collected_at: "2026-06-28T01:37:54".into(),
                symbol_paths: vec!["D:\\Symbols".into()],
                ..Default::default()
            },
            dmp: DmpData {
                exception: ExceptionInfo {
                    code: "C0000005".into(),
                    name: "ACCESS_VIOLATION".into(),
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        // Python uses "meta" and "dmp" as top-level keys
        assert_eq!(parsed["dump_path"], r"C:\dumps\crash.dmp");
        assert_eq!(parsed["exe_dir"], r"C:\MyApp");
        assert_eq!(parsed["dmp"]["exception"]["code"], "C0000005");
    }

    #[test]
    fn test_analyze_options_defaults() {
        let opts = AnalyzeOptions::default();
        assert!(matches!(opts.provider, AiProvider::DeepSeek));
        assert_eq!(opts.timeout_secs, 120);
        assert_eq!(opts.workers, 0);
        assert!(!opts.no_cache);
    }

    #[test]
    fn test_analyze_options_custom() {
        let opts = AnalyzeOptions {
            provider: AiProvider::Anthropic, workers: 4, timeout_secs: 300,
            ..Default::default()
        };
        assert!(matches!(opts.provider, AiProvider::Anthropic));
        assert_eq!(opts.workers, 4);
    }
}
