//! Markdown report generation.
//! Ported from Python mvp/reporter.py — pure string assembly.

pub fn generate_report(
    context_json: &str,
    ai_analysis: &str,
    dump_path: &str,
    collected_at: &str,
) -> String {
    let ctx: serde_json::Value = serde_json::from_str(context_json).unwrap_or_default();
    let dmp = &ctx["dmp"];
    let exception = &dmp["exception"];

    let mut lines = Vec::new();

    // Header
    lines.push(format!("# DMP 崩溃分析报告\n\n**DMP 文件**: `{}`\n**分析时间**: {}\n",
        dump_path, if collected_at.is_empty() { "N/A" } else { collected_at }));

    // Summary
    lines.push("---\n\n## 崩溃摘要\n".into());
    lines.push("| 项目 | 值 |\n|------|-----|".into());
    let proc_name = dmp["metadata"]["process_name"].as_str().unwrap_or("?");
    let ex_code = exception["code"].as_str().unwrap_or("?");
    let ex_name = exception["name"].as_str().unwrap_or("?");
    let ex_addr = exception["address"].as_str().unwrap_or("?");
    lines.push(format!("| 进程 | {} |", proc_name));
    lines.push(format!("| 异常 | **{}** (`{}`) |", ex_name, ex_code));
    lines.push(format!("| 异常地址 | `{}` |", ex_addr));
    lines.push("".into());

    // Exception access type
    if let Some(at) = exception["type"].as_str() {
        if !at.is_empty() && at != "unknown" {
            let addr = exception["attempted_address"].as_str().unwrap_or("N/A");
            lines.push(format!("| 访问类型 | {} -> `{}` |\n", at, addr));
        }
    }

    // Callstack
    let cs = dmp["crash_callstack"].as_array();
    if let Some(frames) = cs {
        if !frames.is_empty() {
            lines.push("## 调用栈\n\n```".into());
            for f in frames {
                let idx = f["frame_index"].as_u64().unwrap_or(0);
                let func = f["function"].as_str().unwrap_or("?");
                let src = if let (Some(file), Some(line)) =
                    (f["source_file"].as_str(), f["source_line"].as_u64()) {
                    format!("  [{}:{}]", file, line)
                } else { String::new() };
                lines.push(format!("  {:2}  {}{}", idx, func, src));
            }
            lines.push("```\n".into());
        }
    }

    // Modules
    let mods = dmp["modules"].as_array();
    if let Some(modules) = mods {
        if !modules.is_empty() {
            lines.push("## 加载模块\n".into());
            lines.push("| 模块 | 版本 | 符号 |\n|------|------|------|".into());
            for m in modules {
                let name = m["name"].as_str().unwrap_or("?");
                let ver = m["version"].as_str().unwrap_or("-");
                let sym = if m["has_symbols"].as_bool().unwrap_or(false) { "Yes" } else { "No" };
                lines.push(format!("| {} | {} | {} |", name, ver, sym));
            }
            lines.push("".into());
        }
    }

    // Heap analysis
    let heap = &dmp["heap"];
    if heap["heap_count"].as_u64().unwrap_or(0) > 0 {
        lines.push("## 内存/堆分析\n".into());
        lines.push(format!("| 堆数量 | {} |\n| 已提交 | {} MB |\n| LFH | {} |",
            heap["heap_count"].as_u64().unwrap_or(0),
            heap["total_committed_mb"].as_u64().unwrap_or(0),
            if heap["lfh_enabled"].as_bool().unwrap_or(false) { "启用" } else { "未启用" },
        ));
        lines.push("".into());
    }

    // AI analysis
    lines.push("---\n\n## AI 分析\n".into());
    lines.push(ai_analysis.to_string());
    lines.push("".into());

    // Footer
    lines.push("---\n\n*报告由 DMP AI Analyzer (Rust) 自动生成*\n".into());

    lines.join("\n")
}

// ═════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_context_json() -> String {
        r#"{
            "dmp": {
                "metadata": {"process_name": "myapp.exe"},
                "exception": {"code": "C0000005", "name": "ACCESS_VIOLATION", "address": "00401234", "type": "read", "attempted_address": "00000000"},
                "crash_callstack": [
                    {"frame_index": 0, "module": "myapp", "function": "myapp!CrashFunc+0x10", "source_file": "main.cpp", "source_line": 42}
                ],
                "modules": [
                    {"name": "myapp.exe", "version": "1.0", "has_symbols": true}
                ],
                "heap": {"heap_count": 3, "total_committed_mb": 128, "lfh_enabled": true}
            }
        }"#.to_string()
    }

    #[test]
    fn test_generate_report_has_header() {
        let report = generate_report(&sample_context_json(), "AI root cause analysis",
                                       "crash.dmp", "2026-06-28T01:00:00");
        assert!(report.contains("DMP 崩溃分析报告"));
        assert!(report.contains("crash.dmp"));
    }

    #[test]
    fn test_generate_report_has_exception() {
        let report = generate_report(&sample_context_json(), "AI result",
                                       "crash.dmp", "");
        assert!(report.contains("ACCESS_VIOLATION"));
        assert!(report.contains("C0000005"));
    }

    #[test]
    fn test_generate_report_has_callstack() {
        let report = generate_report(&sample_context_json(), "AI result",
                                       "crash.dmp", "");
        assert!(report.contains("CrashFunc"));
        assert!(report.contains("main.cpp:42"));
    }

    #[test]
    fn test_generate_report_has_heap() {
        let report = generate_report(&sample_context_json(), "AI result",
                                       "crash.dmp", "");
        assert!(report.contains("内存/堆分析"));
        assert!(report.contains("128 MB"));
    }

    #[test]
    fn test_generate_report_has_ai_section() {
        let report = generate_report(&sample_context_json(), "Root cause: null pointer",
                                       "crash.dmp", "");
        assert!(report.contains("AI 分析"));
        assert!(report.contains("null pointer"));
    }
}
