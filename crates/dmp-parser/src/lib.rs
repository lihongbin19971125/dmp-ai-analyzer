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
        assert_eq!(parse_size_to_mb("1.813 GB"), 1856); // ~1.813*1024
        assert!(parse_size_to_mb("127.992 TB") > 100_000_000); // huge
        assert_eq!(parse_size_to_mb("512 KB"), 0); // < 1MB
    }
}
