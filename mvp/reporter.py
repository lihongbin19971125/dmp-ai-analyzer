"""Markdown report generator.

Combines the structured analysis context and AI analysis result
into a comprehensive Markdown report.
"""

from datetime import datetime


def generate_report(
    context_json: str,
    ai_analysis: str,
    dump_path: str,
    collected_at: str = "",
) -> str:
    """Generate a full Markdown report.

    Args:
        context_json: JSON serialization of AnalysisContext.
        ai_analysis: AI analysis result (Markdown text).
        dump_path: Path to the original DMP file.
        collected_at: ISO timestamp of analysis.

    Returns:
        Complete Markdown report as a string.
    """
    import json as _json
    ctx = _json.loads(context_json)
    dmp = ctx.get("dmp", {})
    exception = dmp.get("exception", {})
    system = dmp.get("system_info", {})
    meta = dmp.get("metadata", {})
    modules = dmp.get("modules", [])

    lines = []

    # ── Header ──
    lines.append(f"# 🔍 DMP 崩溃分析报告")
    lines.append("")
    lines.append(f"**DMP 文件**: `{dump_path}`")
    lines.append(f"**分析时间**: {collected_at or datetime.now().isoformat()}")
    lines.append("")

    # ── Executive Summary ──
    lines.append("---")
    lines.append("")
    lines.append("## 📋 崩溃摘要")
    lines.append("")
    lines.append(f"| 项目 | 值 |")
    lines.append(f"|------|-----|")
    # Process name: prefer metadata, find main EXE from module list, fallback to dump name
    proc_name = meta.get('process_name', '')
    if not proc_name:
        for m in modules:
            mn = m.get('name', '')
            mp = m.get('path', '')
            # Module has .exe extension or path ends with .exe
            if mn.lower().endswith('.exe') or mp.lower().endswith('.exe'):
                proc_name = mn.rsplit('.', 1)[0] if '.' in mn else mn
                break
            # Short name without extension, not a known DLL pattern — likely the EXE
            if '.' not in mn and not mn.lower().startswith(('ntdll','kernel','user','gdi',
                    'combase','ole','msvc','ucrt','advapi','sechost','rpcrt','bcrypt')):
                proc_name = mn
                break
    if not proc_name:
        proc_name = dump_path.replace("\\", "/").split("/")[-1].rsplit(".", 1)[0]
    # Add .exe if no extension
    if "." not in proc_name:
        proc_name += ".exe"

    lines.append(f"| 进程 | {proc_name} (PID: {meta.get('process_id', 'N/A')}) |")
    lines.append(f"| 异常 | **{exception.get('name', 'N/A')}** (`{exception.get('code', 'N/A')}`) |")
    lines.append(f"| 异常地址 | `{exception.get('address', 'N/A')}` |")

    if exception.get("type"):
        addr = exception.get('attempted_address', '')
        lines.append(f"| 访问类型 | {exception.get('type')} → `{addr if addr else 'N/A'}` |")

    lines.append(f"| 崩溃时间 | {meta.get('timestamp', 'N/A')} |")
    lines.append("")

    # ── System Info ──
    if system.get("os_name"):
        lines.append("## 🖥️ 崩溃机器系统信息")
        lines.append("")
        lines.append("| 项目 | 值 |")
        lines.append("|------|-----|")
        lines.append(f"| 操作系统 | {system.get('os_name', '')} {system.get('os_version', '')} (Build {system.get('os_build', '')}) |")
        lines.append(f"| 架构 | {system.get('platform', 'N/A')} |")
        lines.append(f"| CPU | {system.get('cpu_model', 'N/A')} ({system.get('cpu_count', 0)} 核) |")

        features = system.get("cpu_features", [])
        if features:
            lines.append(f"| CPU 特性 | {', '.join(features)} |")

        total_mem = system.get("total_physical_mb", 0)
        avail_mem = system.get("available_physical_mb", 0)
        if total_mem:
            mem_pct = (avail_mem / total_mem * 100) if avail_mem else 0
            lines.append(f"| 物理内存 | {total_mem} MB 总量, {avail_mem} MB 可用 ({mem_pct:.0f}%) |")

        pagefile = system.get("total_pagefile_mb", 0)
        if pagefile:
            lines.append(f"| 页面文件 | {pagefile} MB |")

        ws = system.get("process_working_set_mb", 0)
        pf = system.get("process_pagefile_mb", 0)
        if ws or pf:
            lines.append(f"| 进程内存 | 工作集 {ws} MB, 提交大小 {pf} MB |")

        uptime = system.get("system_uptime_seconds", 0)
        if uptime:
            days = uptime // 86400
            hours = (uptime % 86400) // 3600
            lines.append(f"| 系统运行时间 | {days} 天 {hours} 小时 |")

        if system.get("memory_pressure_reason"):
            lines.append(f"| ⚠️ 内存压力 | **{system['memory_pressure_reason']}** |")

        lines.append("")

    # ── Memory / Heap Analysis ──
    heap = dmp.get("heap", {})
    addr = dmp.get("address_summary", {})
    mem_findings = dmp.get("memory_findings", [])

    # Always show heap section if we have any heap data
    if heap.get("heap_count", 0) > 0 or heap.get("corrupted") or addr:
        lines.append("## 🔍 内存/堆分析")
        lines.append("")

        lines.append("| 指标 | 值 |")
        lines.append("|------|-----|")
        lines.append(f"| 堆数量 | {heap.get('heap_count', 0)} |")
        lines.append(f"| 已提交 | {heap.get('total_committed_mb', 0)} MB |")
        if heap.get("total_reserved_mb", 0) > 0:
            lines.append(f"| 已保留 | {heap.get('total_reserved_mb', 0)} MB |")
        if heap.get("free_bytes", 0) > 0:
            lines.append(f"| 空闲 | {heap.get('free_bytes', 0) // 1024} KB |")
        lines.append(f"| 段数 | {heap.get('segment_count', 0)} |")
        lines.append(f"| LFH | {'✅ 启用' if heap.get('lfh_enabled') else '❌ 未启用'} |")
        lines.append(f"| 堆损坏 | {'⚠️ 是' if heap.get('corrupted') else '✅ 否'} |")
        if addr.get("Free", 0) > 0:
            lines.append(f"| 虚拟地址空闲 | {addr.get('Free', 0)} MB |")
        if addr.get("LargestFreeBlock", 0) > 0:
            lines.append(f"| 最大空闲块 | {addr.get('LargestFreeBlock', 0)} MB |")
        lines.append("")

        # Show findings from MemoryLeakAnalyzer
        if mem_findings:
            lines.append("### ⚠️ 发现的内存问题")
            lines.append("")
            for f in mem_findings:
                sev_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}.get(
                    f.get("severity", "low"), "🟢")
                lines.append(f"**{sev_emoji} [{f.get('severity', '?').upper()}] "
                             f"{f.get('indicator', '?')}**")
                lines.append(f"- 证据: {f.get('evidence', '')}")
                lines.append(f"- 建议: {f.get('recommendation', '')}")
                lines.append("")
        elif heap.get("heap_count", 0) > 0:
            lines.append("✅ 未检测到内存泄漏或异常指标")
            lines.append("")

    # ── Crash Callstack ──
    crash_stack = dmp.get("crash_callstack", [])
    if crash_stack:
        lines.append("## 📚 崩溃调用栈")
        lines.append("")
        lines.append("```")
        for f in crash_stack:
            src = ""
            if f.get("source_file"):
                src = f"  [{f['source_file']}:{f.get('source_line', '')}]"
            lines.append(f"  {f['frame_index']:2d}  {f.get('function', '?')}{src}")
        lines.append("```")
        lines.append("")

    # ── Modules ──
    if modules:
        lines.append("## 📦 加载模块")
        lines.append("")
        lines.append("| 模块 | 版本 | 基址 | 大小 | 符号 |")
        lines.append("|------|------|------|------|------|")

        def _resolve_extension(m: dict) -> str:
            """Guess file extension for a module name."""
            name = m.get("name", "")
            path = m.get("path", "")
            low = name.lower()
            # Already has extension
            if "." in name:
                return name
            # From path if available
            if path:
                import os.path as _osp
                base = _osp.basename(path)
                if "." in base:
                    return base
            # Known DLLs — most Windows system modules
            _KNOWN_DLLS = (
                "ntdll","kernel32","kernelbase","user32","gdi32","gdi32full",
                "combase","ole32","oleaut32","advapi32","sechost","rpcrt4",
                "bcrypt","bcryptprimitives","cryptbase","win32u","imm32",
                "msctf","uxtheme","dwmapi","msvcrt","ucrtbase","ucrtbased",
                "vcruntime140","vcruntime140d","vcruntime140_1","vcruntime140_1d",
                "msvcp140","msvcp_win","concrt140","atl","mfc",
                "version","psapi","kernel_appcore","wow64cpu","wow64win",
                "textinputframework","textshaping","coreuicomponents",
                "coremessaging","oleacc","wintypes","dbghelp","dbgcore",
                "symsrv","srcsrv",
            )
            if low.rstrip("_d") in _KNOWN_DLLS or low.startswith(
                ("ntdll","kernel","user","gdi","ole","combase","msvc","ucrt",
                 "advapi","sechost","rpcrt","bcrypt","win32u","imm32","msctf",
                 "uxtheme","dwmapi","cryptbase","version","psapi","kernel_app",
                 "msvcp","textinput","textshap","coreui","coremess","wow64",
                 "dbghelp","dbgcore","wintypes","vcruntime","concrt")
            ):
                return name + ".dll"
            # Heuristic: very low address (< 0x00800000) is typical for the main EXE.
            # Modules loaded above that are almost always DLLs.
            try:
                base = int(m.get("base_address", "0").replace("`",""), 16)
                if base < 0x00800000:
                    return name + ".exe"
            except (ValueError, AttributeError):
                pass
            return name + ".dll"

        # Sort: symbols first, then by name
        sorted_modules = sorted(modules,
            key=lambda m: (not m.get("has_symbols", False), m.get("name", "").lower()))

        for m in sorted_modules:
            ver = m.get("version") or "-"
            sym = "✅" if m.get("has_symbols") else "❌"
            size_kb = m.get("size", 0) // 1024
            display_name = _resolve_extension(m)
            lines.append(f"| {display_name} | {ver} | `{m.get('base_address', '')}` | {size_kb} KB | {sym} |")
        lines.append("")

    # ── Source Code Snippets ──
    source = ctx.get("source")
    if source:
        snippets = source.get("snippets", [])
        if snippets:
            lines.append("## 💻 崩溃位置源码")
            lines.append("")
            for snip in snippets:
                lines.append(f"**{snip['file_path']}** (crash at line {snip['crash_line']}):")
                lines.append("")
                lines.append("```cpp")
                lines.append(snip.get("code", ""))
                lines.append("```")
                lines.append("")

        changes = source.get("recent_git_changes", [])
        if changes:
            lines.append("### 近期 Git 修改")
            lines.append("")
            for c in changes:
                lines.append(f"- {c}")
            lines.append("")

        if source.get("working_tree_dirty"):
            lines.append("⚠️ **工作区有未提交的修改**")
            lines.append("")

    # ── Logs ──
    logs = ctx.get("logs")
    if logs:
        log_text = logs.get("crash_window_logs", "")
        errors = logs.get("error_summary", [])
        if errors:
            lines.append("## 📝 日志错误摘要")
            lines.append("")
            for e in errors[:20]:
                lines.append(f"- {e}")
            lines.append("")

    # ── Config ──
    config = ctx.get("config")
    if config:
        cfgs = config.get("key_settings", {})
        if cfgs:
            lines.append("## ⚙️ 应用配置")
            lines.append("")
            for filename, content in cfgs.items():
                lines.append(f"**{filename}**:")
                lines.append("```")
                lines.append(content[:2000])
                lines.append("```")
                lines.append("")

    # ── AI Analysis ──
    lines.append("---")
    lines.append("")
    lines.append("## 🤖 AI 分析")
    lines.append("")
    lines.append(ai_analysis)
    lines.append("")

    # ── Footer ──
    lines.append("---")
    lines.append("")
    lines.append("*报告由 DMP AI Analyzer v0.1.0 自动生成*")
    lines.append("")

    return "\n".join(lines)


def md_to_html(md_text: str) -> str:
    """Convert Markdown report to a basic standalone HTML page."""
    # Simple inline conversion for the report structure
    try:
        import markdown
        body = markdown.markdown(md_text, extensions=["tables", "fenced_code"])
    except ImportError:
        # Fallback: wrap in <pre> if markdown unavailable
        body = f"<pre>{md_text}</pre>"

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>DMP 崩溃分析报告</title>
<style>
body {{ font-family: -apple-system, 'Segoe UI', sans-serif; max-width: 900px;
       margin: 40px auto; padding: 0 20px; color: #1a1a1a; line-height: 1.6; }}
h1 {{ border-bottom: 2px solid #e74c3c; padding-bottom: 8px; }}
h2 {{ border-bottom: 1px solid #ddd; padding-bottom: 4px; margin-top: 30px; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
th, td {{ border: 1px solid #ddd; padding: 8px 12px; text-align: left; }}
th {{ background: #f5f5f5; }}
code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 3px; }}
pre {{ background: #f8f8f8; padding: 16px; overflow-x: auto;
      border: 1px solid #e0e0e0; border-radius: 4px; }}
pre code {{ background: none; padding: 0; }}
</style>
</head>
<body>
{body}
</body>
</html>"""


def html_to_pdf(html: str, output_path: str) -> None:
    """Convert HTML to PDF.

    Tries (in order):
    1. Microsoft Edge headless mode (Windows, best CJK support)
    2. WeasyPrint (cross-platform, needs GTK/Pango)
    3. fpdf2 (pure Python, limited CJK)

    Args:
        html: Complete HTML document as a string.
        output_path: Path to write the PDF file.

    Raises:
        ImportError: If no PDF backend is available.
    """
    import tempfile as _tempfile, subprocess as _sp, os as _os, shutil as _shutil

    # 1. Try Microsoft Edge headless (Windows)
    edge_paths = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    ]
    edge_exe = None
    for ep in edge_paths:
        if _os.path.isfile(ep):
            edge_exe = ep
            break
    # Also check PATH
    if edge_exe is None:
        found = _shutil.which("msedge") or _shutil.which("msedge.exe")
        if found:
            edge_exe = found

    if edge_exe:
        try:
            # Write HTML to temp file
            with _tempfile.NamedTemporaryFile(
                mode="w", suffix=".html", delete=False, encoding="utf-8"
            ) as tf:
                tf.write(html)
                tmp_html = tf.name
            try:
                _sp.run(
                    [edge_exe, "--headless", f"--print-to-pdf={output_path}",
                     f"file:///{tmp_html.replace(chr(92), '/')}"],
                    timeout=60, check=True,
                    stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                )
                return
            finally:
                try:
                    _os.unlink(tmp_html)
                except OSError:
                    pass
        except Exception:
            pass

    # 2. Try WeasyPrint
    try:
        from weasyprint import HTML
        HTML(string=html).write_pdf(output_path)
        return
    except ImportError:
        pass
    except Exception:
        pass

    # 3. Fallback: fpdf2
    try:
        from fpdf import FPDF
        _html_to_pdf_fpdf(html, output_path, FPDF)
        return
    except ImportError:
        pass

    raise ImportError(
        "PDF export requires one of: Microsoft Edge, weasyprint, or fpdf2.\n"
        "Install with: pip install weasyprint  (best quality, needs GTK)\n"
        "         or: pip install fpdf2       (pure Python, basic support)"
    ) from None


def _html_to_pdf_fpdf(html: str, output_path: str, FPDF) -> None:
    """Generate PDF from HTML using fpdf2 (basic HTML support)."""
    import re as _re

    pdf = FPDF()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=15)

    # Try to find a suitable font for CJK characters
    font_loaded = False
    font_candidates = [
        r"C:\Windows\Fonts\msyh.ttc",     # Microsoft YaHei
        r"C:\Windows\Fonts\simsun.ttc",    # SimSun
        r"C:\Windows\Fonts\msgothic.ttc",  # MS Gothic
    ]
    for font_path in font_candidates:
        try:
            pdf.add_font("CJK", "", font_path, uni=True)
            pdf.set_font("CJK", "", 10)
            font_loaded = True
            break
        except (OSError, RuntimeError):
            continue

    if not font_loaded:
        # Use built-in font (no CJK support but won't crash)
        pdf.set_font("Helvetica", "", 10)

    # Strip HTML tags and convert basic elements
    text = _re.sub(r"<style[^>]*>.*?</style>", "", html, flags=_re.DOTALL | _re.IGNORECASE)
    text = _re.sub(r"<br\s*/?>", "\n", text, flags=_re.IGNORECASE)
    text = _re.sub(r"</(p|div|h[1-6]|li|tr)>", "\n", text, flags=_re.IGNORECASE)
    text = _re.sub(r"<[^>]+>", "", text)
    text = _re.sub(r"&lt;", "<", text)
    text = _re.sub(r"&gt;", ">", text)
    text = _re.sub(r"&amp;", "&", text)
    text = _re.sub(r"\n{3,}", "\n\n", text)

    # Split into lines and write
    # Use landscape for reports (wider tables/code blocks)
    page_w = pdf.w - pdf.l_margin - pdf.r_margin
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Truncate very long lines to fit page width
        if len(line) > 200:
            line = line[:200] + "..."
        try:
            pdf.multi_cell(page_w, 5, line)
        except Exception:
            # Final fallback: ASCII-only
            try:
                safe = line.encode("ascii", errors="replace").decode("ascii")
                pdf.set_font("Helvetica", "", 8)
                pdf.multi_cell(page_w, 4, safe)
                if font_loaded:
                    pdf.set_font("CJK", "", 10)
                else:
                    pdf.set_font("Helvetica", "", 10)
            except Exception:
                pass

    pdf.output(output_path)


def print_summary(ai_analysis: str) -> None:
    """Print a brief summary to console."""
    # Extract first meaningful heading/sentence
    import re
    # Try to find the root cause section
    m = re.search(
        r"(?:根因|根本原因|Root Cause)[：:]*\s*\n*(.+?)(?:\n|$)",
        ai_analysis, re.IGNORECASE
    )
    if m:
        print(f"\n  [ROOT CAUSE] {m.group(1).strip()[:200]}")
    else:
        # First non-empty non-heading line
        for line in ai_analysis.split("\n"):
            line = line.strip()
            if line and not line.startswith("#"):
                print(f"\n  [SUMMARY] {line[:200]}")
                break
