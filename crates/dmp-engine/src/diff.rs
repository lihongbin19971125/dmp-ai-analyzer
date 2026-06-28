//! Report comparison — diff two existing Markdown reports.
//! Ported from Python mvp/diff.py.

use regex::Regex;
use std::path::Path;

pub fn diff_reports(report1_path: &Path, report2_path: &Path) -> Result<String, String> {
    let t1 = std::fs::read_to_string(report1_path)
        .map_err(|e| format!("Cannot read {}: {}", report1_path.display(), e))?;
    let t2 = std::fs::read_to_string(report2_path)
        .map_err(|e| format!("Cannot read {}: {}", report2_path.display(), e))?;

    let s1 = parse_report_sections(&t1);
    let s2 = parse_report_sections(&t2);

    let mut lines = Vec::new();
    lines.push("# 报告对比分析\n".into());
    lines.push(format!("**报告 1**: `{}`\n**报告 2**: `{}`\n",
        report1_path.display(), report2_path.display()));

    let mut diffs = 0;

    // Exception type
    lines.push("---\n\n## 异常类型\n".into());
    if s1.ex_code == s2.ex_code {
        lines.push(format!("无变化: **{}** (`{}`)\n", s1.ex_name, s1.ex_code));
    } else {
        diffs += 1;
        lines.push("| | 报告 1 | 报告 2 |\n|---|--------|--------|".into());
        lines.push(format!("| 异常 | **{}** (`{}`) | **{}** (`{}`) |\n",
            s1.ex_name, s1.ex_code, s2.ex_name, s2.ex_code));
    }

    // Callstack
    lines.push("## 调用栈对比\n".into());
    let only1: Vec<_> = s1.callstack.iter().filter(|f| !s2.callstack.contains(f)).collect();
    let only2: Vec<_> = s2.callstack.iter().filter(|f| !s1.callstack.contains(f)).collect();
    if !only1.is_empty() || !only2.is_empty() {
        diffs += 1;
        for f in only1.iter().take(10) { lines.push(format!("- ❌ 仅报告1: `{}`", f)); }
        for f in only2.iter().take(10) { lines.push(format!("- ✅ 仅报告2: `{}`", f)); }
    } else {
        lines.push("无变化 — 调用栈完全一致\n".into());
    }
    lines.push("".into());

    // Modules
    lines.push("## 模块版本对比\n".into());
    let mut mod_diffs = 0;
    let all_mods: Vec<&String> = s1.modules.keys()
        .chain(s2.modules.keys())
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter().collect();
    for mn in &all_mods {
        let v1 = s1.modules.get(*mn).map(|s| s.as_str()).unwrap_or("—");
        let v2 = s2.modules.get(*mn).map(|s| s.as_str()).unwrap_or("—");
        if v1 != v2 {
            mod_diffs += 1;
            lines.push(format!("- **{}**: `{}` → `{}`", mn, v1, v2));
        }
    }
    if mod_diffs == 0 {
        lines.push("无变化 — 所有模块版本一致\n".into());
    } else {
        diffs += 1;
    }
    lines.push("".into());

    // Summary
    lines.push("---\n".into());
    if diffs == 0 {
        lines.push("## ✅ 无显著差异\n\n两份报告一致。\n".into());
    } else {
        lines.push(format!("## 📊 发现 {} 处差异\n", diffs));
    }

    Ok(lines.join("\n"))
}

struct ReportSections {
    ex_code: String,
    ex_name: String,
    callstack: Vec<String>,
    modules: std::collections::HashMap<String, String>,
}

fn parse_report_sections(md: &str) -> ReportSections {
    let mut s = ReportSections {
        ex_code: "?".into(),
        ex_name: "?".into(),
        callstack: Vec::new(),
        modules: std::collections::HashMap::new(),
    };

    // Exception: **NAME** (`CODE`)
    if let Some(cap) = Regex::new(r"\*\*(.+?)\*\*\s*\(`([A-F0-9]+)`\)").unwrap().captures(md) {
        s.ex_name = cap[1].to_string();
        s.ex_code = cap[2].to_string();
    }

    // Callstack functions
    let cs_re = Regex::new(r"(\w[\w.]*!\w[\w+<>@]*(?:\+0x[0-9a-f]+)?)").unwrap();
    for cap in cs_re.captures_iter(md) {
        s.callstack.push(cap[1].to_string());
    }

    // Module table rows
    let mod_re = Regex::new(r"\|\s*([\w.]+\.(?:exe|dll|sys|ocx|cpl))\s*\|\s*([\w.\-]*)\s*\|").unwrap();
    for cap in mod_re.captures_iter(md) {
        s.modules.insert(cap[1].to_string(), cap[2].to_string());
    }

    s
}

// ═════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::PathBuf;

    fn write_report(dir: &Path, name: &str, content: &str) -> PathBuf {
        let p = dir.join(name);
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(content.as_bytes()).unwrap();
        p
    }

    #[test]
    fn test_diff_different_exceptions() {
        let tmp = std::env::temp_dir().join(format!("dmp_diff_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let r1 = write_report(&tmp, "r1.md",
            "# Report\n## 崩溃摘要\n| 异常 | **ACCESS_VIOLATION** (`C0000005`) |\n");
        let r2 = write_report(&tmp, "r2.md",
            "# Report\n## 崩溃摘要\n| 异常 | **STACK_OVERFLOW** (`C00000FD`) |\n");
        let diff = diff_reports(&r1, &r2).unwrap();
        assert!(diff.contains("C0000005"));
        assert!(diff.contains("C00000FD"));
    }

    #[test]
    fn test_diff_identical() {
        let tmp = std::env::temp_dir().join(format!("dmp_diff2_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let md = "# Report\n| 异常 | **ACCESS_VIOLATION** (`C0000005`) |\n";
        let r1 = write_report(&tmp, "r1.md", md);
        let r2 = write_report(&tmp, "r2.md", md);
        let diff = diff_reports(&r1, &r2).unwrap();
        assert!(diff.contains("无显著差异"));
    }

    #[test]
    fn test_diff_module_versions() {
        let tmp = std::env::temp_dir().join(format!("dmp_diff3_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let r1 = write_report(&tmp, "r1.md",
            "# Report\n| mylib.dll | 1.0.0.0 |\n");
        let r2 = write_report(&tmp, "r2.md",
            "# Report\n| mylib.dll | 2.0.0.0 |\n");
        let diff = diff_reports(&r1, &r2).unwrap();
        assert!(diff.contains("mylib.dll"));
        assert!(diff.contains("1.0.0.0"));
    }

    #[test]
    fn test_diff_missing_file() {
        let r = diff_reports(Path::new("/nope1.md"), Path::new("/nope2.md"));
        assert!(r.is_err());
    }
}
