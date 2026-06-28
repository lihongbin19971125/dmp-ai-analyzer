//! CDB output parsers — ported from Python mvp/parser.py.
//!
//! All functions are pure computation (regex parsing of text),
//! matching the Python implementation's output exactly.

use dmp_context::*;
use regex::Regex;

// ── Heap parser ──────────────────────────────────────────

pub fn parse_heap_info(raw: &str) -> HeapInfo {
    let mut info = HeapInfo::default();

    // Heap count
    if let Some(cap) = Regex::new(r"(\d+)\s+heaps").unwrap().captures(raw) {
        info.heap_count = cap[1].parse().unwrap_or(0);
    }

    // LFH enabled
    if Regex::new(r"LFH\s+Key:\s*0x[0-9a-f]*[1-9a-f]").unwrap().is_match(raw) {
        info.lfh_enabled = true;
    }

    // Per-heap parsing
    let commit_re = Regex::new(r"(?i)(?:commit(?:ted)?)\s+.*?(\d+)\s*(Mb|MB|kb|KB)").unwrap();
    let reserve_re = Regex::new(r"(?i)(?:reserv(?:ed)?)\s+.*?(\d+)\s*(Mb|MB|kb|KB)").unwrap();
    let free_re = Regex::new(r"(?i)(?:free)\s+.*?(\d+)\s*(bytes|KB|kb|MB|Mb)").unwrap();
    let seg_re = Regex::new(r"(?i)(?:virtual address space|segments?)[:\s]+(\d+)\s*segments?").unwrap();
    let seg_fallback = Regex::new(r"(?i)(\d+)\s*segments?").unwrap();
    let addr_re = Regex::new(r"(?i)Heap\s+([0-9a-f`]+)").unwrap();

    let mut total_committed: u32 = 0;
    let mut total_reserved: u32 = 0;
    let mut total_free: u64 = 0;
    let mut total_segments: u32 = 0;

    // Split raw text into per-heap blocks
    let heap_blocks: Vec<&str> = {
        let mut blocks = Vec::new();
        let mut start_idx = None;
        for (i, _) in raw.match_indices('\n') {
            let rest = &raw[i + 1..];
            if rest.starts_with("Heap ") || rest.starts_with("  Heap ") {
                if let Some(s) = start_idx {
                    blocks.push(&raw[s..i]);
                }
                start_idx = Some(i + 1);
            }
        }
        if let Some(s) = start_idx {
            blocks.push(&raw[s..]);
        }
        if blocks.is_empty() {
            // No per-heap blocks found, whole text is the only block
            blocks.push(raw);
        }
        blocks
    };

    for block in heap_blocks {
        if block.trim().is_empty() {
            continue;
        }
        let heap_addr = addr_re.captures(block)
            .map(|c| c[1].replace('`', ""))
            .unwrap_or_default();

        let mut commit_mb: u32 = 0;
        let mut reserve_mb: u32 = 0;
        let mut free_bytes: u64 = 0;
        let mut segments: u32 = 0;

        for cm in commit_re.captures_iter(block) {
            let val: u32 = cm[1].parse().unwrap_or(0);
            let v = if cm[2].to_lowercase().contains("kb") { val / 1024 } else { val };
            commit_mb += v;
            total_committed += v;
        }
        for rm in reserve_re.captures_iter(block) {
            let val: u32 = rm[1].parse().unwrap_or(0);
            let v = if rm[2].to_lowercase().contains("kb") { val / 1024 } else { val };
            reserve_mb += v;
            total_reserved += v;
        }
        for fm in free_re.captures_iter(block) {
            let val: u64 = fm[1].parse().unwrap_or(0);
            let unit = fm[2].to_lowercase();
            let v = if unit.contains("mb") { val * 1024 * 1024 }
                    else if unit.contains("kb") { val * 1024 }
                    else { val };
            free_bytes += v;
            total_free += v;
        }
        if let Some(sm) = seg_re.captures(block).or_else(|| seg_fallback.captures(block)) {
            segments = sm[1].parse().unwrap_or(0);
            total_segments += segments;
        }

        if !heap_addr.is_empty() {
            info.per_heap_breakdown.push(PerHeapInfo {
                address: heap_addr,
                commit_mb,
                reserve_mb,
                free_bytes,
                segments,
            });
        }
    }

    info.total_committed_mb = total_committed;
    info.total_reserved_mb = total_reserved;
    info.free_bytes = total_free;
    info.segment_count = total_segments;

    // Corruption detection
    let corrupt_re = Regex::new(
        r"(?i)(?:heap.*(?:corrupt|damage|error)|corruption\s+detected|HEAP_CORRUPTION|block.*modified.*after.*freed|use.after.free)"
    ).unwrap();
    if corrupt_re.is_match(raw) {
        info.corrupted = true;
        let detail_re = Regex::new(
            r"(?i)(corrupt|error|invalid|damage|modified|after.*freed)"
        ).unwrap();
        for line in raw.lines() {
            if detail_re.is_match(line)
                && !line.to_lowercase().contains("termination on corruption")
            {
                let s: String = line.trim().chars().take(200).collect();
                info.details.push(s);
            }
        }
    }

    info
}

// ── Address summary parser ───────────────────────────────

pub fn parse_address_summary(raw: &str) -> std::collections::HashMap<String, u64> {
    let mut result = std::collections::HashMap::new();

    let cat_re = Regex::new(
        r"(?i)(\w+)\s+\d+\s+[0-9a-f`]+\s*\(([^)]+)\)"
    ).unwrap();

    for cap in cat_re.captures_iter(raw) {
        let category = cap[1].to_string();
        let size_str = cap[2].to_string();
        result.insert(category, parse_size_to_mb(&size_str));
    }

    // Largest free block
    let lfb_re = Regex::new(
        r"(?i)Largest\s*(?:free)?\s*block[:\s]+[0-9a-f`]+\s*\(([^)]+)\)"
    ).unwrap();
    if let Some(cap) = lfb_re.captures(raw) {
        result.insert("LargestFreeBlock".into(), parse_size_to_mb(&cap[1]));
    }

    result
}

fn parse_size_to_mb(s: &str) -> u64 {
    let re = Regex::new(r"(?i)([\d.]+)\s*(TB|GB|MB|KB|BYTES?)").unwrap();
    if let Some(cap) = re.captures(s.trim()) {
        let value: f64 = cap[1].parse().unwrap_or(0.0);
        let unit = cap[2].to_uppercase();
        match unit.as_str() {
            "TB" => (value * 1024.0 * 1024.0) as u64,
            "GB" => (value * 1024.0) as u64,
            "MB" => value as u64,
            _ => (value / 1024.0) as u64, // KB or bytes
        }
    } else {
        0
    }
}

// ── Exception info parser ────────────────────────────────

const EXCEPTION_CODES: &[(&str, &str)] = &[
    ("C0000005", "ACCESS_VIOLATION"),
    ("C000000D", "STATUS_INVALID_PARAMETER"),
    ("C0000017", "STATUS_NO_MEMORY"),
    ("C00000FD", "STACK_OVERFLOW"),
    ("C0000094", "INTEGER_DIVIDE_BY_ZERO"),
    ("C000008E", "FLOAT_DIVIDE_BY_ZERO"),
    ("C0000374", "HEAP_CORRUPTION"),
    ("C0000409", "STACK_BUFFER_OVERRUN"),
    ("80000003", "BREAKPOINT"),
    ("E0434352", "CLR_EXCEPTION"),
    ("E06D7363", "CPP_EXCEPTION"),
];

pub fn parse_exception_info(raw: &str) -> ExceptionInfo {
    let mut info = ExceptionInfo::default();

    // Exception code: C0000005
    let code_re = Regex::new(r"(?i)(?:ExceptionCode|exception)\s*[:=]?\s*([0-9A-Fa-f]{8,})").unwrap();
    if let Some(cap) = code_re.captures(raw) {
        info.code = cap[1].to_uppercase();
    }
    // Fallback: look for hex code in parentheses
    if info.code.is_empty() {
        let fallback = Regex::new(r"\(([0-9A-Fa-f]{8,})\)").unwrap();
        if let Some(cap) = fallback.captures(raw) {
            info.code = cap[1].to_uppercase();
        }
    }

    // Look up name
    if !info.code.is_empty() {
        info.name = EXCEPTION_CODES.iter()
            .find(|(c, _)| c.eq_ignore_ascii_case(&info.code))
            .map(|(_, n)| n.to_string())
            .unwrap_or_default();
    }

    // Address
    let addr_re = Regex::new(r"(?i)(?:ExceptionAddress|faulting IP|at)\s*[:=]?\s*([0-9a-f`]{8,})").unwrap();
    if let Some(cap) = addr_re.captures(raw) {
        info.address = cap[1].replace('`', "");
    }

    // Access type from Parameter[0]: 0=read, 1=write, 8=execute
    let p0_re = Regex::new(r"Parameter\[0\][:\s]*([0-9a-f]+)").unwrap();
    if let Some(cap) = p0_re.captures(raw) {
        let val = cap[1].trim_start_matches('0');
        info.access_type = match val {
            "" | "0" => "read".into(),
            "1" => "write".into(),
            "8" => "execute".into(),
            _ => "unknown".into(),
        };
    }

    // Attempted address from Parameter[1]
    let p1_re = Regex::new(r"Parameter\[1\][:\s]*([0-9a-f`]+)").unwrap();
    if let Some(cap) = p1_re.captures(raw) {
        info.attempted_address = cap[1].replace('`', "");
    }

    info
}

// ── System info parser ───────────────────────────────────

pub fn parse_system_info(raw: &str) -> SystemInfo {
    let mut si = SystemInfo::default();

    // OS: "Windows 10 Version 26200 MP (12 procs) Free x64"
    let os_re = Regex::new(r"(Windows\s+\S+)\s+Version\s+(\d+)\s+MP\s*\((\d+)\s+procs?\)\s*\w*\s*(\w+)").unwrap();
    if let Some(cap) = os_re.captures(raw) {
        si.os_name = cap[1].to_string();
        si.os_build = cap[2].to_string();
        si.cpu_count = cap[3].parse().unwrap_or(0);
        si.platform = cap[4].to_lowercase();
    }

    // OS version
    let ver_re = Regex::new(r"OS_VERSION:\s*([\d.]+)").unwrap();
    if let Some(cap) = ver_re.captures(raw) {
        si.os_version = cap[1].to_string();
    }

    // Machine name
    let name_re = Regex::new(r"Machine Name:\s*(\S+)").unwrap();
    if let Some(cap) = name_re.captures(raw) {
        si.machine_name = Some(cap[1].to_string());
    }

    // System uptime
    let up_re = Regex::new(r"System Uptime:\s*(?:(\d+)\s*days?\s*)?(?:(\d+):(\d+):(\d+))?").unwrap();
    if let Some(cap) = up_re.captures(raw) {
        let days: u64 = cap.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        let hours: u64 = cap.get(2).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        let mins: u64 = cap.get(3).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        let secs: u64 = cap.get(4).and_then(|m| m.as_str().parse().ok()).unwrap_or(0);
        si.system_uptime_seconds = days * 86400 + hours * 3600 + mins * 60 + secs;
    }

    // CPU model
    let cpu_re = Regex::new(r"Processor:\s*(.+?)(?:\n|$)").unwrap();
    if let Some(cap) = cpu_re.captures(raw) {
        si.cpu_model = cap[1].trim().to_string();
    }

    // CPU features
    let feat_re = Regex::new(r"(SSE2?|SSE3|SSSE3|SSE4\.[12]|AVX2?|AVX512\w*|FMA\d|BMI[12]|RDRAND|RTM)").unwrap();
    for cap in feat_re.captures_iter(raw) {
        si.cpu_features.push(cap[1].to_string());
    }

    // Physical memory (handle "Physical: 0x... ( 16384 Mb )" with optional spaces)
    if let Some(cap) = Regex::new(r"(?i)Physical:\s*[0-9a-f`x]+\s*\(\s*(\d+)\s*Mb").unwrap().captures(raw) {
        si.total_physical_mb = cap[1].parse().unwrap_or(0);
    }
    if let Some(cap) = Regex::new(r"(?i)Avail:\s*[0-9a-f`x]+\s*\(\s*(\d+)\s*Mb").unwrap().captures(raw) {
        si.available_physical_mb = cap[1].parse().unwrap_or(0);
    }
    if let Some(cap) = Regex::new(r"(?i)PageFile:\s*[0-9a-f`x]+\s*\(\s*(\d+)\s*Mb").unwrap().captures(raw) {
        si.total_pagefile_mb = cap[1].parse().unwrap_or(0);
    }
    if let Some(cap) = Regex::new(r"(?i)WorkingSet:\s*[0-9a-f`x]+\s*\(\s*(\d+)\s*Mb").unwrap().captures(raw) {
        si.process_working_set_mb = cap[1].parse().unwrap_or(0);
    }

    // Environment variables
    let env_re = Regex::new(r"(?m)^([A-Z_][A-Z0-9_]*)=(.*)$").unwrap();
    for cap in env_re.captures_iter(raw) {
        si.environment.insert(cap[1].to_string(), cap[2].trim().to_string());
    }

    si
}

// ── Callstack parser ─────────────────────────────────────

pub fn parse_callstack(text: &str) -> Vec<Frame> {
    let mut frames = Vec::new();
    // Frame line: "00 00007ff7`12345678 myapp!main+0x42 [d:\src\main.cpp @ 342]"
    let frame_re = Regex::new(
        r"(?m)^\s*([0-9a-f]{2})\s+[0-9a-f`]+\s+(\w+)!([^+\s]+)(?:\+0x[0-9a-f]+)?\s*(?:\[([^@]+?)\s*@\s*(\d+)\])?"
    ).unwrap();

    for cap in frame_re.captures_iter(text) {
        let idx: u32 = u32::from_str_radix(&cap[1], 16).unwrap_or(0);
        let module = cap[2].to_string();
        let func = format!("{}!{}", module, &cap[3]);
        let source_file = cap.get(4).map(|m| m.as_str().trim().to_string());
        let source_line = cap.get(5).and_then(|m| m.as_str().parse().ok());

        frames.push(Frame {
            frame_index: idx,
            module,
            function: func,
            offset: String::new(),
            source_file,
            source_line,
        });
    }
    frames
}

// ── All threads parser ───────────────────────────────────

pub fn parse_all_threads(raw: &str) -> Vec<ThreadStack> {
    let mut threads = Vec::new();
    // Thread header: "   0  Id: 1a8c.1a90 Crashed <Memory Access Violation>"
    let thread_re = Regex::new(
        r"(?m)^\s+(\d+)\s+Id:\s*[0-9a-f]+\.([0-9a-f]+)\s*(\w+)(?:\s*<(.*?)>)?"
    ).unwrap();

    // Split by thread boundaries
    let parts: Vec<&str> = raw.split('\n').collect();
    let mut current_tid: u32 = 0;
    let mut current_state = String::new();
    let mut current_stack: Vec<String> = Vec::new();

    for line in &parts {
        if let Some(cap) = thread_re.captures(line) {
            // Save previous thread
            if current_tid != 0 && !current_stack.is_empty() {
                let stack_text = current_stack.join("\n");
                threads.push(ThreadStack {
                    thread_id: current_tid,
                    state: current_state.clone(),
                    callstack: parse_callstack(&stack_text),
                });
            }
            current_tid = u32::from_str_radix(&cap[2], 16).unwrap_or(0);
            current_state = cap[3].to_string();
            current_stack = Vec::new();
        } else if current_tid != 0 && !line.trim().is_empty() {
            current_stack.push(line.to_string());
        }
    }
    // Don't forget the last thread
    if current_tid != 0 && !current_stack.is_empty() {
        let stack_text = current_stack.join("\n");
        threads.push(ThreadStack {
            thread_id: current_tid,
            state: current_state,
            callstack: parse_callstack(&stack_text),
        });
    }
    threads
}

// ── Module list parser ───────────────────────────────────

pub fn parse_module_list(raw: &str) -> Vec<ModuleInfo> {
    let mut modules = Vec::new();
    // "00007ff7`12340000 00007ff7`12350000 myapp"
    let header_re = Regex::new(
        r"(?m)^([0-9a-f`]+)\s+([0-9a-f`]+)\s+(\S+)"
    ).unwrap();

    let lines: Vec<&str> = raw.lines().collect();
    let mut i = 0;
    while i < lines.len() {
        if let Some(cap) = header_re.captures(lines[i]) {
            let name = cap[3].to_string();
            // Skip known non-module words
            if matches!(name.to_lowercase().as_str(),
                "ret" | "call" | "jmp" | "start" | "end" | "module") {
                i += 1;
                continue;
            }
            let base = cap[1].replace('`', "");
            let end = cap[2].replace('`', "");
            let size = if let (Ok(b), Ok(e)) =
                (u64::from_str_radix(&base, 16), u64::from_str_radix(&end, 16)) {
                e.saturating_sub(b)
            } else { 0 };

            let mut path = String::new();
            let mut version = None;
            let mut has_symbols = false;

            // Look ahead for detail lines
            for j in (i + 1)..lines.len() {
                let line = lines[j];
                if header_re.is_match(line) { break; }
                if let Some(pm) = Regex::new(r"Image path:\s*(.+)").unwrap().captures(line) {
                    path = pm[1].trim().to_string();
                }
                if let Some(vm) = Regex::new(r"File version:\s*(.+)").unwrap().captures(line) {
                    version = Some(vm[1].trim().to_string());
                }
                if line.contains("symbols loaded") || line.contains("PDB") {
                    has_symbols = true;
                }
            }

            modules.push(ModuleInfo {
                name, path, base_address: base, size,
                version, timestamp: None, has_symbols,
            });
        }
        i += 1;
    }
    modules
}

// ── Register extraction ──────────────────────────────────

pub fn extract_registers(raw: &str) -> std::collections::HashMap<String, String> {
    let mut regs = std::collections::HashMap::new();
    // Support both one-per-line and space-separated formats
    let reg_re = Regex::new(
        r"(?i)(rax|rcx|rdx|rbx|rsp|rbp|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15|rip|eip|eax|ecx|edx|ebx|esp|ebp|esi|edi)\s*=\s*([0-9a-f`]+)"
    ).unwrap();
    for cap in reg_re.captures_iter(raw) {
        regs.insert(cap[1].to_string(), cap[2].replace('`', ""));
    }
    regs
}

// ── Main entry: parse_cdb_output ─────────────────────────

pub fn parse_cdb_output(raw: &str, dump_path: &str) -> DmpData {
    let mut dmp = DmpData::default();

    dmp.system_info = parse_system_info(raw);
    dmp.exception = parse_exception_info(raw);
    dmp.crash_callstack = extract_crash_callstack(raw);
    dmp.all_callstacks = parse_all_threads(raw);
    dmp.registers = extract_registers(raw);
    dmp.raw_analyze_output = raw.to_string();

    // Detect dump type from filename
    let lower = dump_path.to_lowercase();
    dmp.metadata.dump_type = if lower.contains("kernel") { "kernel".into() }
        else if lower.contains("full") { "full".into() }
        else { "minidump".into() };

    dmp.metadata.timestamp = extract_crash_time(raw);
    dmp.metadata.process_name = extract_process_name(raw);

    dmp
}

fn extract_crash_callstack(raw: &str) -> Vec<Frame> {
    // Extract from `.ecxr` context or STACK_TEXT section
    let st_re = Regex::new(r"(?is)STACK_TEXT:?\s*\n(.*?)(?:\n\n|\z)").unwrap();
    if let Some(cap) = st_re.captures(raw) {
        return parse_callstack(&cap[1]);
    }
    // Fallback: LAST_CONTROL_TRANSFER
    let lct_re = Regex::new(r"(?is)LAST_CONTROL_TRANSFER:.*?\n(.*?)(?:\n\n|\z)").unwrap();
    if let Some(cap) = lct_re.captures(raw) {
        return parse_callstack(&cap[1]);
    }
    Vec::new()
}

fn extract_crash_time(raw: &str) -> String {
    let time_re = Regex::new(r"Debug session time:\s*(.+)").unwrap();
    time_re.captures(raw)
        .map(|c| c[1].trim().to_string())
        .unwrap_or_default()
}

fn extract_process_name(raw: &str) -> String {
    let pn_re = Regex::new(r"Process Name:\s*(\S+\.exe)").unwrap();
    pn_re.captures(raw)
        .map(|c| c[1].to_string())
        .unwrap_or_default()
}

// ── Memory Leak Analyzer ─────────────────────────────────

/// Memory leak detection from heap statistics and system state.
pub struct MemoryLeakAnalyzer {
    heap: dmp_context::HeapInfo,
    sys: dmp_context::SystemInfo,
    addr: std::collections::HashMap<String, u64>,
}

const HIGH_COMMIT_PER_HEAP_MB: u32 = 100;
const HIGH_RESERVED_RATIO: f64 = 3.0;
const LOW_FREE_VIRTUAL_MB: u64 = 100;
const HIGH_HEAP_COUNT: u32 = 20;
const LONG_UPTIME_SECONDS: u64 = 86400 * 7;
const HIGH_UPTIME_COMMIT_MB: u32 = 500;
const HIGH_FRAGMENTATION_RATIO: f64 = 0.5;

impl MemoryLeakAnalyzer {
    pub fn new(dmp: &DmpData) -> Self {
        Self {
            heap: dmp.heap.clone(),
            sys: dmp.system_info.clone(),
            addr: dmp.address_summary.clone(),
        }
    }

    pub fn analyze(&self) -> Vec<MemoryFinding> {
        let mut findings = Vec::new();

        for check in [
            Self::check_high_commit,
            Self::check_reserved_ratio,
            Self::check_virtual_exhaustion,
            Self::check_commit_vs_physical,
            Self::check_heap_count,
            Self::check_lfh_status,
            Self::check_uptime_correlation,
            Self::check_corruption,
            Self::check_fragmentation,
        ] {
            if let Some(f) = check(self) {
                findings.push(f);
            }
        }
        findings
    }

    pub fn pressure_reason(findings: &[MemoryFinding]) -> String {
        if findings.is_empty() { return String::new(); }
        let high: Vec<_> = findings.iter().filter(|f| f.severity == "high").collect();
        if !high.is_empty() {
            format!("检测到 {} 个严重内存问题: {}", high.len(),
                high.iter().take(3).map(|f| f.indicator.as_str()).collect::<Vec<_>>().join("; "))
        } else {
            format!("检测到 {} 个内存异常指标", findings.len())
        }
    }

    fn check_high_commit(&self) -> Option<MemoryFinding> {
        let avg = self.heap.total_committed_mb as f64 / self.heap.heap_count.max(1) as f64;
        if avg > HIGH_COMMIT_PER_HEAP_MB as f64 {
            Some(MemoryFinding {
                indicator: "high_commit".into(), severity: "high".into(),
                evidence: format!("堆平均提交 {:.0}MB (阈值 {}MB)", avg, HIGH_COMMIT_PER_HEAP_MB),
                recommendation: "检查是否存在内存泄漏，使用 !heap -s -v 查看每堆详情".into(),
            })
        } else { None }
    }

    fn check_reserved_ratio(&self) -> Option<MemoryFinding> {
        if self.heap.total_committed_mb == 0 { return None; }
        let ratio = self.heap.total_reserved_mb as f64 / self.heap.total_committed_mb as f64;
        if ratio > HIGH_RESERVED_RATIO {
            Some(MemoryFinding {
                indicator: "high_reserved_ratio".into(), severity: "high".into(),
                evidence: format!("保留/提交比 {:.1}:1 (阈值 {}:1)", ratio, HIGH_RESERVED_RATIO),
                recommendation: "高保留比表示堆碎片严重，考虑使用 LFH 或自定义分配器".into(),
            })
        } else { None }
    }

    fn check_virtual_exhaustion(&self) -> Option<MemoryFinding> {
        let free = self.addr.get("Free").copied().unwrap_or(0);
        if free > 0 && free < LOW_FREE_VIRTUAL_MB {
            Some(MemoryFinding {
                indicator: "virtual_exhaustion".into(), severity: "high".into(),
                evidence: format!("虚拟地址空闲仅 {}MB (阈值 {}MB)", free, LOW_FREE_VIRTUAL_MB),
                recommendation: "虚拟地址接近耗尽，即使物理内存充足也会分配失败。检查虚拟内存碎片".into(),
            })
        } else { None }
    }

    fn check_commit_vs_physical(&self) -> Option<MemoryFinding> {
        let total = self.sys.process_working_set_mb + self.sys.process_pagefile_mb;
        if total > 0 && total as f64 > self.sys.total_physical_mb as f64 * 0.8 {
            Some(MemoryFinding {
                indicator: "commit_exceeds_ram".into(), severity: "high".into(),
                evidence: format!("进程提交 {}MB > 物理内存 80% ({}MB)", total, self.sys.total_physical_mb),
                recommendation: "进程提交量已超过物理内存，可能触发页面文件交换导致性能下降".into(),
            })
        } else { None }
    }

    fn check_heap_count(&self) -> Option<MemoryFinding> {
        if self.heap.heap_count > HIGH_HEAP_COUNT {
            Some(MemoryFinding {
                indicator: "high_heap_count".into(), severity: "medium".into(),
                evidence: format!("{} 个堆 (阈值 {})", self.heap.heap_count, HIGH_HEAP_COUNT),
                recommendation: "大量堆可能由 DLL 各自创建堆导致".into(),
            })
        } else { None }
    }

    fn check_lfh_status(&self) -> Option<MemoryFinding> {
        if !self.heap.lfh_enabled && self.heap.total_committed_mb > 50 {
            Some(MemoryFinding {
                indicator: "lfh_disabled".into(), severity: "medium".into(),
                evidence: format!("堆提交 {}MB 但 LFH 未启用", self.heap.total_committed_mb),
                recommendation: "启用低碎片堆 (LFH) 以减少内存碎片".into(),
            })
        } else { None }
    }

    fn check_uptime_correlation(&self) -> Option<MemoryFinding> {
        if self.sys.system_uptime_seconds > LONG_UPTIME_SECONDS
            && self.heap.total_committed_mb > HIGH_UPTIME_COMMIT_MB
        {
            let hours = self.sys.system_uptime_seconds / 3600;
            Some(MemoryFinding {
                indicator: "uptime_leak_correlation".into(), severity: "high".into(),
                evidence: format!("运行 {}h, 堆提交 {}MB", hours, self.heap.total_committed_mb),
                recommendation: "长时间运行伴随高提交量 → 可能存在慢速内存泄漏".into(),
            })
        } else { None }
    }

    fn check_corruption(&self) -> Option<MemoryFinding> {
        if self.heap.corrupted {
            let details = self.heap.details.first().cloned().unwrap_or("堆损坏检测阳性".into());
            Some(MemoryFinding {
                indicator: "heap_corruption".into(), severity: "high".into(),
                evidence: details.chars().take(200).collect(),
                recommendation: "堆已损坏。可能是 use-after-free 或缓冲区溢出".into(),
            })
        } else { None }
    }

    fn check_fragmentation(&self) -> Option<MemoryFinding> {
        if self.heap.total_reserved_mb > 0 && self.heap.free_bytes > 0 {
            let ratio = self.heap.free_bytes as f64 / (self.heap.total_reserved_mb as f64 * 1024.0 * 1024.0);
            if ratio > HIGH_FRAGMENTATION_RATIO {
                Some(MemoryFinding {
                    indicator: "high_fragmentation".into(), severity: "medium".into(),
                    evidence: format!("碎片率 {:.0}% (free/reserved), 空闲 {}KB",
                        ratio * 100.0, self.heap.free_bytes / 1024),
                    recommendation: "高碎片率导致内存利用率低。考虑合并小分配、使用内存池或启用 LFH".into(),
                })
            } else { None }
        } else { None }
    }
}

// ═════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    // ── Sample data (from Python test suite) ─────────────

    const SAMPLE_HEAP_ENHANCED: &str = r"5 heaps found
LFH Key: 0x7ffe12345678
Termination on corruption: ENABLED

  Heap 0000012340000000
    Reserved 0000000002000000 (32768 KB)
    Committed 0000000001500000 (21504 KB)
    Free 0000000000080000 (512 KB)
    Virtual address space: 8 segments

  Heap 0000012340010000
    Reserved 0000000001000000 (16384 KB)
    Committed 0000000000800000 (8192 KB)
    Free 0000000000040000 (256 KB)
    Virtual address space: 3 segments

  Heap 0000012340020000
    Reserved 0000000000080000 (512 KB)
    Committed 0000000000040000 (256 KB)
    Free 0000000000010000 (64 KB)
    Virtual address space: 2 segments
";

    const SAMPLE_HEAP_EMPTY: &str = r"0 heaps found
LFH Key: 0x0
Termination on corruption: DISABLED
";

    const SAMPLE_ADDRESS_SUMMARY: &str = r"
--- Usage Summary ---------------- RgnCount ----------- Total Size -------- %ofBusy %ofTotal
Free                                     45          7ffe`00000000 ( 127.992 TB)           65.00%
Image                                   342            7`3f4b0000 (   1.813 GB)  25.00%    8.75%
Heap                                     55            2`8a3b0000 ( 650.000 MB)   8.90%    3.11%
Stack                                    12              8c000000 (   2.188 GB)  30.00%   10.50%

--- Largest Free Block by Region -
Largest free block: 7ffd`f0000000 ( 127.980 TB)
";

    const SAMPLE_EXCEPTION: &str = r"EXCEPTION_RECORD:  ffffffffffffffff -- (.exr 0xffffffffffffffff)
ExceptionAddress: 00007ff8`abcd1234
ExceptionCode: C0000005 (Access violation)
Parameter[0]: 0000000000000000
Parameter[1]: 0000000000000000
";

    // ── Heap tests ──────────────────────────────────────

    #[test]
    fn test_parse_heap_enhanced_fields() {
        let h = parse_heap_info(SAMPLE_HEAP_ENHANCED);
        assert_eq!(h.heap_count, 5);
        assert!(h.lfh_enabled);
        assert!(h.total_committed_mb > 25);  // 21504+8192+256 KB ≈ 29MB
        assert!(h.total_reserved_mb > 40);   // 32768+16384+512 KB ≈ 48MB
        assert_eq!(h.segment_count, 13);      // 8+3+2
        assert!(!h.corrupted);
        assert_eq!(h.per_heap_breakdown.len(), 3);
        assert_eq!(h.per_heap_breakdown[0].commit_mb, 21); // 21504KB
    }

    #[test]
    fn test_parse_heap_empty() {
        let h = parse_heap_info(SAMPLE_HEAP_EMPTY);
        assert_eq!(h.heap_count, 0);
        assert_eq!(h.total_committed_mb, 0);
        assert!(!h.lfh_enabled);
        assert_eq!(h.segment_count, 0);
    }

    // ── Address summary tests ───────────────────────────

    #[test]
    fn test_parse_address_summary_free() {
        let a = parse_address_summary(SAMPLE_ADDRESS_SUMMARY);
        assert!(a.get("Free").unwrap() > &1_000_000);
        assert!(a.get("Image").unwrap() > &0);
        assert!(a.get("Heap").unwrap() > &0);
    }

    #[test]
    fn test_parse_address_summary_largest_free() {
        let a = parse_address_summary(SAMPLE_ADDRESS_SUMMARY);
        assert!(a.get("LargestFreeBlock").unwrap() > &0);
    }

    #[test]
    fn test_parse_address_summary_empty() {
        let a = parse_address_summary("");
        assert!(a.is_empty());
    }

    // ── Exception tests ─────────────────────────────────

    #[test]
    fn test_parse_exception_access_violation() {
        let e = parse_exception_info(SAMPLE_EXCEPTION);
        assert_eq!(e.code, "C0000005");
        assert_eq!(e.name, "ACCESS_VIOLATION");
        assert!(!e.address.is_empty());
        assert_eq!(e.access_type, "read"); // Parameter[0] = 0
        assert_eq!(e.attempted_address, "0000000000000000");
    }

    #[test]
    fn test_parse_exception_unknown_code() {
        let raw = "ExceptionCode: BEEF1234";
        let e = parse_exception_info(raw);
        assert_eq!(e.code, "BEEF1234");
        assert!(e.name.is_empty()); // not in known codes
    }

    // ── Size parsing ────────────────────────────────────

    #[test]
    fn test_parse_size_to_mb_values() {
        assert_eq!(parse_size_to_mb("650.000 MB"), 650);
        assert_eq!(parse_size_to_mb("1.813 GB"), 1856);
        assert!(parse_size_to_mb("127.992 TB") > 100_000_000);
        assert_eq!(parse_size_to_mb("512 KB"), 0);
    }

    // ── System info tests ────────────────────────────────

    const SAMPLE_SYSTEM_INFO: &str = r"Windows 10 Version 26200 MP (12 procs) Free x64
Product: WinNt, suite: SingleUserTS
Machine Name: DESKTOP-CRASH01
OSNAME: Windows 10 Pro
OS_VERSION: 10.0.26200.1
OSPLATFORM_TYPE: x64
System Uptime: 3 days 7:22:15
Processor: Intel(R) Core(TM) i7-13700K
PageFile: 0x0000000200000000 ( 8192 Mb )
Physical: 0x0000000040000000 ( 16384 Mb )
Avail: 0x0000000010000000 ( 4096 Mb )
WorkingSet: 0x0000000008000000 ( 2048 Mb )
COMPUTERNAME=DESKTOP-CRASH01
TEMP=C:\Temp
";

    #[test]
    fn test_parse_system_info_basic() {
        let si = parse_system_info(SAMPLE_SYSTEM_INFO);
        assert_eq!(si.os_name, "Windows 10");
        assert_eq!(si.os_build, "26200");
        assert_eq!(si.cpu_count, 12);
        assert_eq!(si.platform, "x64");
        assert_eq!(si.total_physical_mb, 16384);
        assert_eq!(si.available_physical_mb, 4096);
        assert_eq!(si.process_working_set_mb, 2048);
    }

    #[test]
    fn test_parse_system_info_uptime() {
        let si = parse_system_info(SAMPLE_SYSTEM_INFO);
        // 3 days 7:22:15 = 3*86400 + 7*3600 + 22*60 + 15 = 259200 + 25200 + 1320 + 15 = 285735
        assert!(si.system_uptime_seconds > 280_000);
        assert!(si.system_uptime_seconds < 290_000);
    }

    #[test]
    fn test_parse_system_info_env() {
        let si = parse_system_info(SAMPLE_SYSTEM_INFO);
        assert_eq!(si.environment.get("COMPUTERNAME").map(|s| s.as_str()), Some("DESKTOP-CRASH01"));
        assert_eq!(si.environment.get("TEMP").map(|s| s.as_str()), Some(r"C:\Temp"));
    }

    // ── Callstack tests ──────────────────────────────────

    const SAMPLE_CALLSTACK: &str = r"00 00007ff7`12345678 myapp!main+0x42 [d:\src\main.cpp @ 342]
01 00007ff7`12346780 myapp!WorkerThread+0x120 [d:\src\worker.cpp @ 156]
02 00007ff7`12347000 libcore!ProcessData+0x3f4
03 00007fff`abcd1234 ntdll!RtlUserThreadStart+0x20
";

    #[test]
    fn test_parse_callstack_basic() {
        let frames = parse_callstack(SAMPLE_CALLSTACK);
        assert_eq!(frames.len(), 4);
        assert_eq!(frames[0].frame_index, 0);
        assert_eq!(frames[0].module, "myapp");
        assert!(frames[0].function.contains("main"));
        assert_eq!(frames[0].source_file.as_deref(), Some(r"d:\src\main.cpp"));
        assert_eq!(frames[0].source_line, Some(342));
    }

    #[test]
    fn test_parse_callstack_no_source() {
        let frames = parse_callstack(SAMPLE_CALLSTACK);
        // Frame 2 has no source info
        assert!(frames[2].source_file.is_none());
        assert!(frames[2].source_line.is_none());
    }

    #[test]
    fn test_parse_callstack_empty() {
        let frames = parse_callstack("");
        assert!(frames.is_empty());
    }

    // ── Thread tests ─────────────────────────────────────

    const SAMPLE_THREADS: &str = r"   0  Id: 1a8c.1a90 Crashed <Memory Access Violation>
00 00007ff6`11111111 myapp!CrashFunc+0x10
01 00007ff6`22222222 myapp!main+0x42

   1  Id: 1a8c.1a94 Waiting:UserRequest
00 00007fff`33333333 ntdll!NtWaitForSingleObject+0x14
";

    #[test]
    fn test_parse_all_threads_count() {
        let threads = parse_all_threads(SAMPLE_THREADS);
        assert_eq!(threads.len(), 2);
    }

    #[test]
    fn test_parse_all_threads_state() {
        let threads = parse_all_threads(SAMPLE_THREADS);
        assert_eq!(threads[0].state, "Crashed");
    }

    // ── Module tests ─────────────────────────────────────

    const SAMPLE_MODULES: &str = r"start    end        module name
00007ff7`12340000 00007ff7`12350000 myapp
    Image path: C:\Program Files\MyApp\myapp.exe
    File version: 1.2.3.4
    PDB: myapp.pdb (symbols loaded)

00007fff`abcd0000 00007fff`abcf0000 ntdll
    Image path: C:\Windows\System32\ntdll.dll
";

    #[test]
    fn test_parse_module_list_count() {
        let mods = parse_module_list(SAMPLE_MODULES);
        assert_eq!(mods.len(), 2);
    }

    #[test]
    fn test_parse_module_list_details() {
        let mods = parse_module_list(SAMPLE_MODULES);
        assert_eq!(mods[0].name, "myapp");
        assert_eq!(mods[0].version.as_deref(), Some("1.2.3.4"));
        assert!(mods[0].has_symbols);
        assert!(mods[0].size > 0);
    }

    // ── Register tests ───────────────────────────────────

    #[test]
    fn test_extract_registers_x64() {
        let raw = r"rax=0000000000000000 rbx=00007ff612345678 rcx=0000000000000001
rip=00007ff610000000 rsp=000000325717c500";
        let regs = extract_registers(raw);
        assert_eq!(regs.get("rax").map(|s| s.as_str()), Some("0000000000000000"));
        assert_eq!(regs.get("rip").map(|s| s.as_str()), Some("00007ff610000000"));
        assert_eq!(regs.len(), 5);
    }

    // ── Integration tests ────────────────────────────────

    const SAMPLE_FULL_CDB: &str = r"Debug session time: Mon Jun 23 15:26:44.000 2026 (UTC + 8:00)

Windows 10 Version 26200 MP (12 procs) Free x64
Machine Name: DESKTOP-CRASH01
System Uptime: 1 days 2:00:00
Processor: Intel(R) Core(TM) i7-13700K
Physical: 0x0000000040000000 ( 16384 Mb )
Avail: 0x0000000008000000 ( 2048 Mb )

ExceptionCode: C0000005 (Access violation)
ExceptionAddress: 00007ff6`12345678
Process Name: myapp.exe

STACK_TEXT:
00 00007ff6`11111111 myapp!CrashFunc+0x10 [d:\src\main.cpp @ 42]
01 00007ff6`22222222 myapp!WndProc+0x88 [d:\src\wnd.cpp @ 156]
02 00007fff`33333333 ntdll!RtlUserThreadStart+0x20
";

    #[test]
    fn test_parse_cdb_output_integration() {
        let dmp = parse_cdb_output(SAMPLE_FULL_CDB, "crash.dmp");
        assert_eq!(dmp.exception.code, "C0000005");
        assert_eq!(dmp.metadata.dump_type, "minidump");
        assert!(dmp.metadata.timestamp.contains("Jun"));
        assert!(!dmp.crash_callstack.is_empty());
        assert_eq!(dmp.crash_callstack[0].source_line, Some(42));
    }

    #[test]
    fn test_parse_cdb_output_detect_kernel() {
        let dmp = parse_cdb_output(SAMPLE_FULL_CDB, "kernel.dmp");
        assert_eq!(dmp.metadata.dump_type, "kernel");
    }

    // ── MemoryLeakAnalyzer tests ─────────────────────────

    fn make_dmp_for_memory(
        heap_committed: u32, heap_reserved: u32, heap_count: u32,
        free_bytes: u64, lfh_enabled: bool, corrupted: bool,
        total_physical: u32, avail_physical: u32, process_ws: u32,
        process_pf: u32, uptime: u64, free_virtual: u64,
    ) -> DmpData {
        DmpData {
            heap: HeapInfo {
                total_committed_mb: heap_committed,
                total_reserved_mb: heap_reserved,
                heap_count,
                free_bytes,
                lfh_enabled,
                corrupted,
                ..Default::default()
            },
            system_info: SystemInfo {
                total_physical_mb: total_physical,
                available_physical_mb: avail_physical,
                process_working_set_mb: process_ws,
                process_pagefile_mb: process_pf,
                system_uptime_seconds: uptime,
                ..Default::default()
            },
            address_summary: {
                let mut m = std::collections::HashMap::new();
                m.insert("Free".into(), free_virtual);
                m.insert("Heap".into(), heap_committed as u64);
                m
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_memory_high_commit_detected() {
        let dmp = make_dmp_for_memory(600, 800, 5, 0, true, false, 16384, 8192, 128, 256, 3600, 100_000);
        let analyzer = MemoryLeakAnalyzer::new(&dmp);
        let findings = analyzer.analyze();
        assert!(findings.iter().any(|f| f.indicator == "high_commit"));
    }

    #[test]
    fn test_memory_healthy_no_findings() {
        let dmp = make_dmp_for_memory(50, 80, 2, 0, true, false, 32768, 16384, 128, 200, 3600, 10_000_000);
        let analyzer = MemoryLeakAnalyzer::new(&dmp);
        let findings = analyzer.analyze();
        assert!(findings.is_empty());
    }

    #[test]
    fn test_memory_corruption_detected() {
        let dmp = make_dmp_for_memory(200, 400, 3, 0, true, true, 16384, 8192, 128, 256, 3600, 100_000);
        let analyzer = MemoryLeakAnalyzer::new(&dmp);
        let findings = analyzer.analyze();
        assert!(findings.iter().any(|f| f.indicator == "heap_corruption"));
    }

    #[test]
    fn test_memory_virtual_exhaustion() {
        let dmp = make_dmp_for_memory(200, 400, 3, 0, true, false, 16384, 8192, 128, 256, 3600, 50);
        let analyzer = MemoryLeakAnalyzer::new(&dmp);
        let findings = analyzer.analyze();
        assert!(findings.iter().any(|f| f.indicator == "virtual_exhaustion"));
    }

    #[test]
    fn test_memory_lfh_disabled() {
        let dmp = make_dmp_for_memory(500, 800, 10, 0, false, false, 16384, 8192, 128, 256, 3600, 100_000);
        let analyzer = MemoryLeakAnalyzer::new(&dmp);
        let findings = analyzer.analyze();
        assert!(findings.iter().any(|f| f.indicator == "lfh_disabled"));
    }

    #[test]
    fn test_memory_pressure_reason() {
        let findings = vec![
            MemoryFinding { indicator: "high_commit".into(), severity: "high".into(),
                evidence: "...".into(), recommendation: "...".into() },
            MemoryFinding { indicator: "lfh_disabled".into(), severity: "medium".into(),
                evidence: "...".into(), recommendation: "...".into() },
        ];
        let reason = MemoryLeakAnalyzer::pressure_reason(&findings);
        assert!(reason.contains("严重"));
        // Empty findings = empty reason
        assert!(MemoryLeakAnalyzer::pressure_reason(&[]).is_empty());
    }
}
