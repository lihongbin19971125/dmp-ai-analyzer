"""Batch analysis mode — process multiple DMP files and produce a
comparative summary report.

Supports parallel CDB execution via ThreadPoolExecutor for faster
batch processing of multiple DMP files.
"""

import json
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Optional


# ──────────────────────────────────────────────────────────────
# Two-phase pipeline (parallel CDB → serial AI)
# ──────────────────────────────────────────────────────────────

def collect_context(
    dump_path: str,
    exe_dir: Optional[str] = None,
    source_dir: Optional[str] = None,
    symbol_paths: Optional[list[str]] = None,
    cdb_path: Optional[str] = None,
    timeout: int = 120,
    no_cache: bool = False,
) -> dict:
    """Phase 1: Run CDB + collectors to gather structured context.

    This is I/O-bound (CDB reads DMP, writes temp files) and can be
    safely parallelized across multiple DMPs.

    Returns:
        dict with keys: dump_path, ctx, json, error.
        ai_result and report_path are empty; filled by analyze_context().
    """
    result: dict = {
        "dump_path": dump_path,
        "ctx": None,
        "json": "",
        "ai_result": "",
        "report_path": "",
        "error": None,
    }

    try:
        from .context import AnalysisContext
        from .collectors.dmp_collector import DmpCollector
        from .collectors.binary_collector import BinaryCollector
        from .collectors.symbol_collector import SymbolCollector
        from .collectors.log_collector import LogCollector
        from .collectors.eventlog_collector import EventLogCollector
        from .collectors.source_collector import SourceCollector
        from .collectors.config_collector import ConfigCollector

        ctx = AnalysisContext(
            dump_path=str(Path(dump_path).resolve()),
            exe_dir=str(Path(exe_dir).resolve()) if exe_dir else None,
            source_dir=str(Path(source_dir).resolve()) if source_dir else None,
            symbol_paths=symbol_paths or [],
            collected_at=datetime.now().isoformat(),
        )

        collectors = [
            DmpCollector(cdb_path=cdb_path, timeout=timeout,
                         no_cache=no_cache),
            BinaryCollector(),
            SymbolCollector(),
            LogCollector(),
            EventLogCollector(),
            SourceCollector(),
            ConfigCollector(),
        ]

        for collector in collectors:
            if collector.is_applicable(ctx):
                try:
                    ctx = collector.collect(ctx)
                except Exception:
                    pass  # non-fatal

        result["ctx"] = ctx
        result["json"] = json.dumps(ctx.to_dict(), ensure_ascii=False, indent=2)

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


def analyze_context(
    result: dict,
    provider: str = "deepseek",
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    json_only: bool = False,
) -> dict:
    """Phase 2: Run AI analysis and generate report for a collected context.

    This phase is serialized to avoid API rate limits.

    Returns:
        The same result dict with ai_result and report_path filled.
    """
    if result["error"] is not None:
        return result

    try:
        ctx = result["ctx"]
        context_json = result["json"]

        if json_only:
            return result

        from .ai_client import analyze
        from .template_selector import select_template
        exception_code = ctx.dmp.exception.code if ctx.dmp else ""
        prompt_template = select_template(exception_code)

        ai_result = analyze(
            context_json=context_json,
            prompt_template=prompt_template,
            provider=provider,
            api_key=api_key,
            model=model,
        )
        result["ai_result"] = ai_result

        from .reporter import generate_report
        dump_path = result["dump_path"]
        out = str(Path(dump_path).with_suffix("")) + "_report.md"
        report = generate_report(context_json, ai_result, dump_path,
                                 collected_at=ctx.collected_at)
        Path(out).write_text(report, encoding="utf-8")
        result["report_path"] = out

    except Exception as e:
        result["error"] = f"{type(e).__name__}: {e}"

    return result


# ──────────────────────────────────────────────────────────────
# Legacy single-file wrapper (kept for backward compatibility)
# ──────────────────────────────────────────────────────────────

def analyze_single(
    dump_path: str,
    exe_dir: Optional[str] = None,
    source_dir: Optional[str] = None,
    symbol_paths: Optional[list[str]] = None,
    cdb_path: Optional[str] = None,
    timeout: int = 120,
    provider: str = "deepseek",
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    json_only: bool = False,
    verbose: bool = False,
    no_cache: bool = False,
) -> dict:
    """Run the full pipeline on a single DMP (legacy, sequential).

    This calls collect_context() then analyze_context() in sequence.
    Kept for backward compatibility with CLI single-file mode.
    """
    result = collect_context(
        dump_path=dump_path,
        exe_dir=exe_dir,
        source_dir=source_dir,
        symbol_paths=symbol_paths,
        cdb_path=cdb_path,
        timeout=timeout,
        no_cache=no_cache,
    )
    if verbose and result["error"]:
        print(f"  [WARN] {result['error']}")

    return analyze_context(
        result,
        provider=provider,
        api_key=api_key,
        model=model,
        json_only=json_only,
    )


# ──────────────────────────────────────────────────────────────
# BatchRunner
# ──────────────────────────────────────────────────────────────

class BatchRunner:
    """Collect DMP files and run analysis on each.

    Uses two-phase execution:
    1. Parallel CDB + collectors (I/O-bound, safe to parallelize)
    2. Serial AI analysis (protects against API rate limits)
    """

    def __init__(
        self,
        exe_dir: Optional[str] = None,
        source_dir: Optional[str] = None,
        symbol_paths: Optional[list[str]] = None,
        cdb_path: Optional[str] = None,
        timeout: int = 120,
        provider: str = "deepseek",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        json_only: bool = False,
        verbose: bool = False,
        no_cache: bool = False,
        workers: Optional[int] = None,
    ):
        self.exe_dir = exe_dir
        self.source_dir = source_dir
        self.symbol_paths = symbol_paths or []
        self.cdb_path = cdb_path
        self.timeout = timeout
        self.provider = provider
        self.api_key = api_key
        self.model = model
        self.json_only = json_only
        self.verbose = verbose
        self.no_cache = no_cache
        self.workers = workers  # None = auto: min(4, len(files))

    def _collect_files(self, patterns: list[str]) -> list[str]:
        """Expand glob patterns into a sorted, deduplicated file list."""
        seen = set()
        files = []

        def _add(p: Path) -> None:
            if p.suffix.lower() in (".dmp", ".mdmp", ".hdmp"):
                key = str(p.resolve())
                if key not in seen:
                    seen.add(key)
                    files.append(key)

        for pat in patterns:
            p = Path(pat)
            # Existing file
            if p.is_file():
                _add(p)
                continue
            # Glob pattern (may match nothing)
            if "*" in pat or "?" in pat:
                base = Path(pat)
                parent = base.parent if base.parent != Path(".") else Path(".")
                for match in sorted(parent.glob(base.name)):
                    if match.is_file():
                        _add(match)
                continue
            # Possibly a non-existent file path — accept as-is for
            # testing and error-resilience (the caller handles missing files)
            if p.suffix.lower() in (".dmp", ".mdmp", ".hdmp"):
                files.append(str(p.resolve()))
        return files

    def run(self, patterns: list[str]) -> list[dict]:
        """Run full pipeline on each DMP found from the patterns.

        Phase 1 (parallel): CDB + collectors for all DMPs.
        Phase 2 (serial): AI analysis + report generation for each DMP.

        Returns:
            List of result dicts (one per DMP), in crash-time order.
        """
        files = self._collect_files(patterns)
        if not files:
            return []

        # Determine workers
        workers = self.workers
        if workers is None:
            workers = min(4, len(files))
        workers = max(1, workers)

        if self.verbose:
            print(f"\n  [batch] {len(files)} DMP files, {workers} parallel CDB workers")

        # ── Phase 1: Parallel CDB + collectors ──
        results: list[dict] = []
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    collect_context,
                    dump_path=f,
                    exe_dir=self.exe_dir,
                    source_dir=self.source_dir,
                    symbol_paths=self.symbol_paths,
                    cdb_path=self.cdb_path,
                    timeout=self.timeout,
                    no_cache=self.no_cache,
                ): f for f in files
            }
            for i, future in enumerate(as_completed(futures), 1):
                f = futures[future]
                try:
                    result = future.result()
                except Exception as e:
                    result = {
                        "dump_path": f,
                        "ctx": None, "json": "", "ai_result": "",
                        "report_path": "",
                        "error": f"{type(e).__name__}: {e}",
                    }
                results.append(result)
                if self.verbose and not result["error"]:
                    ctx = result["ctx"]
                    ex = ctx.dmp.exception if ctx else None
                    if ex:
                        print(f"  [batch {i}/{len(files)}] {Path(f).name}: "
                              f"{ex.name}({ex.code})")
                elif self.verbose and result["error"]:
                    print(f"  [batch {i}/{len(files)}] {Path(f).name}: "
                          f"ERROR ({result['error'][:60]})")

        # ── Phase 2: Serial AI analysis ──
        for i, r in enumerate(results, 1):
            if r["error"] is not None:
                continue
            fname = Path(r["dump_path"]).name
            if self.verbose:
                print(f"  [AI {i}/{len(results)}] {fname} ...")
            analyze_context(
                r,
                provider=self.provider,
                api_key=self.api_key,
                model=self.model,
                json_only=self.json_only,
            )

        # Sort by crash timestamp
        results.sort(key=lambda r: self._timestamp_key(r))
        return results

    @staticmethod
    def _timestamp_key(result: dict) -> str:
        """Extract timestamp for sorting."""
        ctx = result.get("ctx")
        if ctx and ctx.dmp.metadata.timestamp:
            return ctx.dmp.metadata.timestamp
        return "z"  # sort to end


# ──────────────────────────────────────────────────────────────
# BatchReporter
# ──────────────────────────────────────────────────────────────

class BatchReporter:
    """Generate batch summary markdown report."""

    def generate(
        self,
        results: list[dict],
        exe_dir: Optional[str] = None,
        correlate: bool = False,
    ) -> str:
        """Generate a batch summary report from a list of analysis results.

        Args:
            results: List of result dicts from BatchRunner.run().
            exe_dir: Optional EXE directory for context.
            correlate: If True, include cross-DMP correlation analysis section.

        Returns:
            Markdown report string.
        """
        lines = []
        lines.append("# 批量崩溃分析汇总")
        lines.append("")
        lines.append(f"**分析时间**: {datetime.now().isoformat()}")
        lines.append(f"**DMP 数量**: {len(results)}")
        if exe_dir:
            lines.append(f"**EXE 目录**: `{exe_dir}`")
        lines.append("")

        if not results:
            lines.append("> 无 DMP 文件可分析。")
            return "\n".join(lines)

        successful = [r for r in results if r["error"] is None]
        failed = [r for r in results if r["error"] is not None]

        # Sort by crash timestamp
        def _ts(r: dict) -> str:
            ctx = r.get("ctx")
            return ctx.dmp.metadata.timestamp if ctx else "z"
        successful.sort(key=_ts)
        # Full list also sorted
        all_sorted = sorted(results, key=lambda r: _ts(r) if r["error"] is None else "z")

        # ── Overview table ──
        lines.append("---")
        lines.append("")
        lines.append("## 📊 概览")
        lines.append("")
        lines.append("| # | DMP 文件 | 崩溃时间 | 异常 | 模块 | 根因 | 状态 |")
        lines.append("|---|----------|----------|------|------|------|------|")
        for i, r in enumerate(all_sorted, 1):
            fname = Path(r["dump_path"]).name
            if r["error"]:
                lines.append(f"| {i} | {fname} | - | - | - | {r['error'][:60]} | ❌ |")
                continue
            ctx = r["ctx"]
            ex = ctx.dmp.exception
            ts = ctx.dmp.metadata.timestamp or "-"
            if len(ts) > 19:
                ts = ts[:19]  # truncate long timestamps
            mod = ctx.dmp.crash_callstack[0].module if ctx.dmp.crash_callstack else "-"
            # Extract a 1-line root cause from AI result
            root = self._extract_root_cause(r.get("ai_result", ""))
            lines.append(
                f"| {i} | {fname} | {ts} | **{ex.name}** ({ex.code}) | "
                f"{mod} | {root} | ✅ |"
            )
        lines.append("")

        # ── Success/fail summary ──
        if failed:
            lines.append(f"✅ {len(successful)} 成功 &nbsp; ❌ {len(failed)} 失败")
            lines.append("")
            lines.append("### 失败详情")
            lines.append("")
            for r in failed:
                lines.append(f"- **{Path(r['dump_path']).name}**: {r['error']}")
            lines.append("")

        if not successful:
            return "\n".join(lines)

        # ── Clustering by exception ──
        lines.append("---")
        lines.append("")
        lines.append("## 🔗 异常聚类")
        lines.append("")
        clusters: dict[str, list[dict]] = {}
        for r in successful:
            ex = r["ctx"].dmp.exception
            key = f"{ex.name} ({ex.code})"
            clusters.setdefault(key, []).append(r)
        for key, group in sorted(clusters.items(), key=lambda x: -len(x[1])):
            lines.append(f"### {key} — {len(group)} 次")
            lines.append("")
            for r in group:
                fname = Path(r["dump_path"]).name
                ts = r["ctx"].dmp.metadata.timestamp or "?"
                lines.append(f"- {fname} ({ts})")
            lines.append("")

        # ── Module frequency ──
        lines.append("---")
        lines.append("")
        lines.append("## 📦 崩溃模块统计")
        lines.append("")
        mod_count: dict[str, int] = {}
        for r in successful:
            cs = r["ctx"].dmp.crash_callstack
            if cs:
                mod_count[cs[0].module] = mod_count.get(cs[0].module, 0) + 1
        lines.append("| 模块 | 崩溃次数 |")
        lines.append("|------|---------|")
        for mod, count in sorted(mod_count.items(), key=lambda x: -x[1]):
            lines.append(f"| {mod} | {count} |")
        lines.append("")

        # ── Timeline ──
        lines.append("---")
        lines.append("")
        lines.append("## 🕐 时间线")
        lines.append("")
        for r in successful:
            fname = Path(r["dump_path"]).name
            ts = r["ctx"].dmp.metadata.timestamp or "?"
            ex = r["ctx"].dmp.exception
            lines.append(f"- **{ts}** — {fname} — {ex.name} ({ex.code})")
        lines.append("")

        # ── Individual reports ──
        lines.append("---")
        lines.append("")
        lines.append("## 📄 单独报告")
        lines.append("")
        for r in successful:
            fname = Path(r["dump_path"]).name
            rpt = r.get("report_path", "")
            lines.append(f"- [{fname}]({rpt})")
        lines.append("")

        # ── Correlation analysis (optional) ──
        if correlate and len(successful) >= 2:
            try:
                ca = CorrelationAnalyzer(results)
                lines.append(ca.generate_correlation_report())
                lines.append("")
            except ValueError as e:
                lines.append(f"> ⚠️ 关联分析跳过: {e}")
                lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("*报告由 DMP AI Analyzer v0.2.0 批量模式自动生成*")
        lines.append("")

        return "\n".join(lines)

    @staticmethod
    def _extract_root_cause(ai_text: str) -> str:
        """Extract a 1-line root cause summary from AI analysis text."""
        if not ai_text:
            return "-"
        import re
        # Try to find "根本原因" section
        m = re.search(r"根本原因[：:]\s*\*?\*?(.+?)(?:\n|$)", ai_text)
        if m:
            return m.group(1).strip()[:80]
        # Try "Root Cause"
        m = re.search(r"(?:Root Cause|root cause)[：:]\s*(.+?)(?:\n|$)", ai_text)
        if m:
            return m.group(1).strip()[:80]
        # First meaningful line after AI heading
        for line in ai_text.split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and len(line) > 20:
                return line[:80]
        return "-"


# ──────────────────────────────────────────────────────────────
# CorrelationAnalyzer — cross-DMP pattern mining
# ──────────────────────────────────────────────────────────────

class CorrelationAnalyzer:
    """Analyze relationships across multiple DMP results.

    Performs data-level correlation (no AI needed): callstack similarity,
    system state commonality, module version cross-reference, crash
    frequency trends, and DMP similarity ranking.

    Also prepares compressed summaries for optional AI comprehensive analysis.

    Hard limit: 10 DMPs maximum.
    """

    MAX_DMPS = 10

    def __init__(self, results: list[dict]):
        if len(results) > self.MAX_DMPS:
            raise ValueError(
                f"Correlation analysis supports at most {self.MAX_DMPS} DMPs, "
                f"got {len(results)}. Please reduce the number of files."
            )
        self.results = [r for r in results if r["error"] is None]
        self.failed = [r for r in results if r["error"] is not None]
        self._successful = self.results  # alias for readability

    # ── Callstack similarity ─────────────────────────────────

    def _callstack_similarity(self) -> list[dict]:
        """Pairwise callstack similarity based on Frame 0 function.

        Returns:
            List of {dmp1, dmp2, similarity, same_function} dicts.
        """
        pairs = []
        for i in range(len(self._successful)):
            for j in range(i + 1, len(self._successful)):
                r1 = self._successful[i]
                r2 = self._successful[j]
                fn1 = self._crash_func(r1)
                fn2 = self._crash_func(r2)
                same = fn1 == fn2
                # Compute similarity: same function → 1.0, same module → 0.5
                if same:
                    sim = 1.0
                else:
                    mod1 = fn1.split("!")[0] if "!" in fn1 else ""
                    mod2 = fn2.split("!")[0] if "!" in fn2 else ""
                    if mod1 == mod2 and mod1:
                        # Same module, different function
                        func1 = fn1.split("!")[1].split("+")[0] if "!" in fn1 else fn1
                        func2 = fn2.split("!")[1].split("+")[0] if "!" in fn2 else fn2
                        sim = 0.85 if func1 == func2 else 0.5
                    else:
                        sim = 0.0
                pairs.append({
                    "dmp1": Path(r1["dump_path"]).name,
                    "dmp2": Path(r2["dump_path"]).name,
                    "similarity": sim,
                    "same_function": same,
                    "func1": fn1,
                    "func2": fn2,
                })
        return pairs

    @staticmethod
    def _crash_func(result: dict) -> str:
        """Extract Frame 0 function name from a result."""
        ctx = result.get("ctx")
        if ctx and ctx.dmp.crash_callstack:
            return ctx.dmp.crash_callstack[0].function or "?"
        return "?"

    # ── System state commonality ──────────────────────────────

    def _system_state_commonality(self) -> list[str]:
        """Detect common system state patterns across DMPs.

        Returns:
            List of finding strings.
        """
        findings = []
        total = len(self._successful)
        if total < 2:
            return findings

        # Memory pressure: available < 5% of total
        low_mem_count = 0
        for r in self._successful:
            si = r["ctx"].dmp.system_info
            if si.total_physical_mb > 0:
                pct = si.available_physical_mb / si.total_physical_mb
                if pct < 0.05:
                    low_mem_count += 1
        if low_mem_count >= total * 0.5:
            findings.append(
                f"**内存压力**: {low_mem_count}/{total} ({low_mem_count/total*100:.0f}%) "
                f"的 DMP 崩溃时可用内存不足 5% → 内存耗尽可能是共同因素"
            )

        # High uptime: > 7 days
        high_uptime_count = 0
        for r in self._successful:
            uptime = r["ctx"].dmp.system_info.system_uptime_seconds
            if uptime > 86400 * 7:
                high_uptime_count += 1
        if high_uptime_count >= total * 0.5:
            findings.append(
                f"**长时间运行**: {high_uptime_count}/{total} ({high_uptime_count/total*100:.0f}%) "
                f"的 DMP 系统运行时间超过 7 天 → 可能存在资源泄漏"
            )

        return findings

    # ── Module version cross-reference ───────────────────────

    def _module_version_cross_ref(self) -> list[str]:
        """Cross-reference module versions across DMPs.

        Returns:
            List of finding strings for modules with version discrepancies.
        """
        findings = []
        # Collect all module versions across DMPs
        mod_versions: dict[str, dict[str, set[str]]] = {}
        # mod_versions[module_name] = {version: {dmp_name, ...}}

        for r in self._successful:
            dmp_name = Path(r["dump_path"]).name
            ctx = r["ctx"]
            for mod in ctx.dmp.modules:
                if not mod.name or not mod.version:
                    continue
                mn = mod.name.lower()
                if mn not in mod_versions:
                    mod_versions[mn] = {}
                if mod.version not in mod_versions[mn]:
                    mod_versions[mn][mod.version] = set()
                mod_versions[mn][mod.version].add(dmp_name)

        for mn, versions in mod_versions.items():
            if len(versions) > 1:
                # Module has different versions across DMPs
                ver_list = ", ".join(
                    f"v{v} ({len(dmps)} DMP)" for v, dmps in versions.items()
                )
                findings.append(f"**{mn}**: 版本不一致 — {ver_list}")

        return sorted(findings)

    # ── Crash frequency trend ────────────────────────────────

    def _crash_frequency_trend(self) -> str | None:
        """Analyze crash interval trend over time.

        Returns:
            Trend description string, or None if insufficient data.
        """
        if len(self._successful) < 3:
            return None

        # Extract timestamps
        import re as _re
        from datetime import datetime as _dt

        timestamps = []
        for r in self._successful:
            ts = r["ctx"].dmp.metadata.timestamp
            if not ts:
                continue
            try:
                # Try ISO format
                ts_clean = _re.sub(r"\s*\(.*?\)", "", ts).strip()
                timestamps.append(_dt.fromisoformat(ts_clean))
            except (ValueError, TypeError):
                continue

        if len(timestamps) < 3:
            return "数据不足，无法分析频率趋势（需要至少 3 个有效时间戳）"

        timestamps.sort()
        intervals = []
        for i in range(1, len(timestamps)):
            delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
            intervals.append(delta)

        if len(intervals) < 2:
            return "数据不足，无法分析频率趋势"

        # Check if intervals are decreasing (crash accelerating)
        first_half = intervals[:len(intervals)//2]
        second_half = intervals[len(intervals)//2:]
        avg_first = sum(first_half) / len(first_half)
        avg_second = sum(second_half) / len(second_half)

        if avg_second < avg_first * 0.5:
            return (
                f"⚠️ **崩溃频率加速恶化**: 早期平均间隔 {avg_first/3600:.1f}h, "
                f"后期 {avg_second/3600:.1f}h (缩短 {100*(1-avg_second/avg_first):.0f}%)"
            )
        elif avg_second < avg_first * 0.8:
            return (
                f"**崩溃频率上升**: 早期 {avg_first/3600:.1f}h → "
                f"后期 {avg_second/3600:.1f}h"
            )
        else:
            return f"**崩溃频率稳定**: 间隔约 {sum(intervals)/len(intervals)/3600:.1f}h"

    # ── DMP similarity ranking ───────────────────────────────

    def _similarity_ranking(self) -> list[dict]:
        """Rank DMP pairs by overall similarity.

        Combines callstack, exception type, and system state similarity.
        """
        pairs = self._callstack_similarity()
        # Boost similarity for same exception code
        for pair in pairs:
            r1 = self._find_result(pair["dmp1"])
            r2 = self._find_result(pair["dmp2"])
            if r1 and r2:
                ex1 = r1["ctx"].dmp.exception.code
                ex2 = r2["ctx"].dmp.exception.code
                if ex1 == ex2:
                    pair["similarity"] = min(1.0, pair["similarity"] + 0.1)
        pairs.sort(key=lambda p: -p["similarity"])
        return pairs

    def _find_result(self, dmp_name: str) -> dict | None:
        for r in self._successful:
            if Path(r["dump_path"]).name == dmp_name:
                return r
        return None

    # ── Compressed summaries for AI ──────────────────────────

    def _compress_summaries(self) -> list[str]:
        """Compress each DMP result into a ~2KB summary for AI analysis.

        Excludes raw CDB output and large source code blocks.
        """
        summaries = []
        for r in self._successful:
            ctx = r["ctx"]
            ex = ctx.dmp.exception
            si = ctx.dmp.system_info
            cs = ctx.dmp.crash_callstack[:5]  # Top 5 frames
            mods = ctx.dmp.modules[:20]  # Top 20 modules

            parts = [
                f"DMP: {Path(r['dump_path']).name}",
                f"时间: {ctx.dmp.metadata.timestamp or '?'}",
                f"异常: {ex.name} ({ex.code}) @ {ex.address}",
            ]
            if cs:
                parts.append("调用栈:")
                for f in cs:
                    src = f" [{f.source_file}:{f.source_line}]" if f.source_file else ""
                    parts.append(f"  {f.frame_index} {f.function}{src}")
            parts.append(
                f"系统: {si.os_name} {si.platform}, "
                f"内存 {si.available_physical_mb}/{si.total_physical_mb}MB, "
                f"运行 {si.system_uptime_seconds//3600}h"
            )
            if mods:
                parts.append("模块: " + ", ".join(
                    f"{m.name}({m.version or '-'})" for m in mods
                ))

            summaries.append("\n".join(parts))

        return summaries

    # ── Generate correlation report ──────────────────────────

    def generate_correlation_report(self) -> str:
        """Generate a Markdown correlation analysis section.

        This is appended to the batch summary report.
        """
        lines = []
        lines.append("---")
        lines.append("")
        lines.append("## 🔬 关联分析")
        lines.append("")

        if len(self._successful) < 2:
            lines.append("> 数据不足，需要至少 2 个成功分析的 DMP 才能进行关联分析。")
            return "\n".join(lines)

        # ── Callstack similarity ──
        pairs = self._callstack_similarity()
        high_sim = [p for p in pairs if p["similarity"] >= 0.8]
        if high_sim:
            lines.append("### 📚 调用栈高度相似")
            lines.append("")
            for p in high_sim[:10]:
                lines.append(
                    f"- **{p['dmp1']}** ↔ **{p['dmp2']}**: "
                    f"相似度 {p['similarity']*100:.0f}% "
                    f"(`{p['func1']}`)"
                )
            lines.append("")

        # ── System state commonality ──
        sys_findings = self._system_state_commonality()
        if sys_findings:
            lines.append("### 🖥️ 系统状态共因")
            lines.append("")
            for f in sys_findings:
                lines.append(f"- {f}")
            lines.append("")

        # ── Module version cross-reference ──
        mod_findings = self._module_version_cross_ref()
        if mod_findings:
            lines.append("### 📦 模块版本差异")
            lines.append("")
            for f in mod_findings:
                lines.append(f"- {f}")
            lines.append("")

        # ── Crash frequency ──
        freq = self._crash_frequency_trend()
        if freq:
            lines.append("### 🕐 崩溃频率趋势")
            lines.append("")
            lines.append(freq)
            lines.append("")

        # ── Similarity ranking ──
        ranking = self._similarity_ranking()
        if ranking:
            lines.append("### 🔗 DMP 相似度排名")
            lines.append("")
            lines.append("| 排名 | DMP 1 | DMP 2 | 相似度 | 同一函数 |")
            lines.append("|------|-------|-------|--------|---------|")
            for i, p in enumerate(ranking[:15], 1):
                check = "✅" if p["same_function"] else "❌"
                lines.append(
                    f"| {i} | {p['dmp1']} | {p['dmp2']} | "
                    f"{p['similarity']*100:.0f}% | {check} |"
                )
            lines.append("")

        # ── Compressed summaries for AI ──
        lines.append("### 📝 DMP 压缩摘要")
        lines.append("")
        summaries = self._compress_summaries()
        for s in summaries:
            lines.append("```")
            lines.append(s[:2000])
            lines.append("```")
            lines.append("")

        return "\n".join(lines)


# ──────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────

def run_batch(
    patterns: list[str],
    exe_dir: Optional[str] = None,
    source_dir: Optional[str] = None,
    symbol_paths: Optional[list[str]] = None,
    cdb_path: Optional[str] = None,
    timeout: int = 120,
    provider: str = "deepseek",
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    json_only: bool = False,
    verbose: bool = False,
    output: Optional[str] = None,
    no_cache: bool = False,
    correlate: bool = False,
    workers: Optional[int] = None,
) -> int:
    """Run batch analysis and return exit code.

    Args:
        patterns: List of DMP file paths or glob patterns.
        output: Path for the batch summary report.
        correlate: If True, add cross-DMP correlation analysis.

    Returns:
        0 on success, 1 on total failure.
    """
    runner = BatchRunner(
        exe_dir=exe_dir,
        source_dir=source_dir,
        symbol_paths=symbol_paths,
        cdb_path=cdb_path,
        timeout=timeout,
        provider=provider,
        api_key=api_key,
        model=model,
        json_only=json_only,
        verbose=verbose,
        no_cache=no_cache,
        workers=workers,
    )

    print(f"\n  [batch] 收集 DMP 文件...")
    results = runner.run(patterns)

    if not results:
        print("  [batch] 未找到 DMP 文件")
        return 1

    # Generate summary
    reporter = BatchReporter()
    summary = reporter.generate(results, exe_dir=exe_dir, correlate=correlate)

    out_path = output or "batch_summary.md"
    Path(out_path).write_text(summary, encoding="utf-8")
    print(f"\n  [batch] 汇总报告: {out_path}")

    # Quick stats
    ok = sum(1 for r in results if r["error"] is None)
    fail = len(results) - ok
    print(f"  [batch] 完成: {ok} 成功, {fail} 失败 (共 {len(results)} 个 DMP)")

    return 0 if ok > 0 else 1
