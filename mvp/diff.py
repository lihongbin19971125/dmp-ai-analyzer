"""Report comparison mode — diff two DMP analysis reports.

Extracts key sections from Markdown reports and generates a unified
comparison highlighting differences in exception, callstack, modules,
and system state.
"""

import re
from datetime import datetime
from pathlib import Path


def _parse_report_sections(md_text: str) -> dict:
    """Parse key sections from a Markdown report into a structured dict.

    Returns:
        dict with keys: exception_code, exception_name, modules (list of
        (name, version) tuples), callstack (list of function strings),
        system_info (raw text), process_name, timestamp.
    """
    sections = {
        "exception_code": "?",
        "exception_name": "?",
        "modules": [],
        "callstack": [],
        "system_info": "",
        "process_name": "?",
        "timestamp": "?",
    }

    # Exception: **NAME** (`CODE`)
    m = re.search(r"\*\*(.+?)\*\*\s*\(`([A-F0-9]+)`\)", md_text)
    if m:
        sections["exception_name"] = m.group(1).strip()
        sections["exception_code"] = m.group(2).strip()

    # Process name
    m = re.search(r"进程\s*\|\s*(.+?)\s*\(PID:", md_text)
    if m:
        sections["process_name"] = m.group(1).strip()

    # Timestamp
    m = re.search(r"崩溃时间\s*\|\s*(.+?)\s*\|", md_text)
    if m:
        sections["timestamp"] = m.group(1).strip()

    # Module table rows
    for m in re.finditer(
        r"\|\s*([\w.]+\.(?:exe|dll|sys|ocx|cpl))\s*\|\s*([\w.\-]*)\s*\|",
        md_text, re.IGNORECASE,
    ):
        sections["modules"].append((m.group(1), m.group(2) or "-"))

    # Callstack functions
    in_callstack = False
    for line in md_text.split("\n"):
        if "##" in line and ("调用栈" in line or "Callstack" in line or "Call Stack" in line):
            in_callstack = True
            continue
        if in_callstack and line.startswith("##"):
            in_callstack = False
            continue
        if in_callstack:
            # Extract function from: "   0  module!Function+offset"
            fm = re.search(r"(\w[\w.]*!\w[\w+<>@]*(?:\+0x[0-9a-f]+)?)", line)
            if fm:
                sections["callstack"].append(fm.group(1))

    # System info section
    sys_match = re.search(
        r"##\s*[^\n]*系统信息[^\n]*\n(.*?)(?=\n##|\Z)", md_text, re.DOTALL
    )
    if sys_match:
        sections["system_info"] = sys_match.group(1).strip()

    return sections


def diff_reports(report1_path: str, report2_path: str) -> str:
    """Compare two Markdown reports and produce a diff summary.

    Args:
        report1_path: Path to first report (.md).
        report2_path: Path to second report (.md).

    Returns:
        Markdown diff report string.

    Raises:
        FileNotFoundError: If either report file doesn't exist.
    """
    p1 = Path(report1_path)
    p2 = Path(report2_path)
    if not p1.is_file():
        raise FileNotFoundError(f"Report not found: {report1_path}")
    if not p2.is_file():
        raise FileNotFoundError(f"Report not found: {report2_path}")

    t1 = p1.read_text(encoding="utf-8")
    t2 = p2.read_text(encoding="utf-8")

    s1 = _parse_report_sections(t1)
    s2 = _parse_report_sections(t2)

    lines = []
    lines.append("# 报告对比分析")
    lines.append("")
    lines.append(f"**报告 1**: `{report1_path}`")
    lines.append(f"**报告 2**: `{report2_path}`")
    lines.append(f"**对比时间**: {datetime.now().isoformat()}")
    lines.append("")

    differences = 0

    # ── Exception type ──
    lines.append("---")
    lines.append("")
    lines.append("## 异常类型")
    lines.append("")
    if s1["exception_code"] == s2["exception_code"]:
        lines.append(f"无变化: **{s1['exception_name']}** (`{s1['exception_code']}`)")
    else:
        differences += 1
        lines.append("⚠️ **异常类型变化**")
        lines.append("")
        lines.append("| | 报告 1 | 报告 2 |")
        lines.append("|---|--------|--------|")
        lines.append(f"| 异常 | **{s1['exception_name']}** (`{s1['exception_code']}`) | "
                     f"**{s2['exception_name']}** (`{s2['exception_code']}`) |")
    lines.append("")

    # ── Process ──
    if s1["process_name"] != s2["process_name"]:
        differences += 1
        lines.append(f"⚠️ 进程名变化: `{s1['process_name']}` → `{s2['process_name']}`")
        lines.append("")

    # ── Callstack ──
    lines.append("---")
    lines.append("")
    lines.append("## 调用栈对比")
    lines.append("")
    cs1 = s1["callstack"]
    cs2 = s2["callstack"]
    common = set(cs1) & set(cs2)
    only1 = [f for f in cs1 if f not in common]
    only2 = [f for f in cs2 if f not in common]
    if only1 or only2:
        differences += 1
        for f in only1[:10]:
            lines.append(f"- ❌ 仅报告1: `{f}`")
        for f in only2[:10]:
            lines.append(f"- ✅ 仅报告2: `{f}`")
    if common:
        lines.append(f"\n共同帧: {len(common)}")
    if not only1 and not only2:
        lines.append("无变化 — 调用栈完全一致")
    lines.append("")

    # ── Modules ──
    lines.append("---")
    lines.append("")
    lines.append("## 模块版本对比")
    lines.append("")
    mod1 = dict(s1["modules"])
    mod2 = dict(s2["modules"])
    all_mods = sorted(set(mod1.keys()) | set(mod2.keys()))
    mod_diffs = 0
    for mn in all_mods:
        v1 = mod1.get(mn, "—")
        v2 = mod2.get(mn, "—")
        if v1 != v2:
            mod_diffs += 1
            lines.append(f"- **{mn}**: `{v1}` → `{v2}`")
    if mod_diffs == 0:
        lines.append("无变化 — 所有模块版本一致")
    else:
        differences += 1
        lines.append(f"\n{mod_diffs} 个模块版本有变化")
    lines.append("")

    # ── System info ──
    if s1["system_info"] != s2["system_info"]:
        differences += 1
        lines.append("---")
        lines.append("")
        lines.append("## 系统环境变化")
        lines.append("")
        lines.append("```")
        lines.append(f"--- 报告 1 ---\n{s1['system_info'][:500]}")
        lines.append(f"\n--- 报告 2 ---\n{s2['system_info'][:500]}")
        lines.append("```")
        lines.append("")

    # ── Summary ──
    lines.append("---")
    lines.append("")
    if differences == 0:
        lines.append("## ✅ 无显著差异")
        lines.append("")
        lines.append("两份报告在异常类型、调用栈、模块版本上完全一致。")
    else:
        lines.append(f"## 📊 发现 {differences} 处差异")
    lines.append("")

    lines.append("---")
    lines.append("*报告由 DMP AI Analyzer v0.2.0 对比模式自动生成*")
    lines.append("")

    return "\n".join(lines)
