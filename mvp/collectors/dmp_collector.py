"""DMP core analysis collector.

Runs CDB against the dump file and parses all output into structured data.
This is the only mandatory collector — it provides the foundation for all others.

Supports caching of CDB output via CacheManager to avoid re-running CDB
for previously analyzed DMP files.
"""

from typing import Optional

from ..cache_manager import CacheManager
from ..cdb_runner import find_cdb, run_cdb
from ..context import AnalysisContext
from ..parser import (parse_cdb_output, parse_module_list, parse_heap_info,
                       parse_locks, parse_address_summary)
from .base import BaseCollector


class DmpCollector(BaseCollector):
    """Collect crash dump core data using CDB.

    Uses a two-pass strategy:
    1. First pass: .ecxr + k + ~* k + vertarget + !analyze -v
       (symbols from EXE dir give full function names and source lines)
    2. Second pass: lm + !heap -s + !locks
       (avoids CDB command-line length limit and output interleaving)
    """

    name = "dmp_collector"

    def __init__(self, cdb_path: str | None = None, timeout: int = 120,
                 no_cache: bool = False):
        self.cdb_path = cdb_path
        self.timeout = timeout
        self.no_cache = no_cache
        self._cache = CacheManager() if not no_cache else None

    def is_applicable(self, ctx: AnalysisContext) -> bool:
        """Always applicable — this is the foundation collector."""
        return True

    def collect(self, ctx: AnalysisContext) -> AnalysisContext:
        print(f"  [{self.name}] 启动 CDB 分析 {ctx.dump_path} ...")

        cdb = find_cdb(self.cdb_path)
        print(f"  [{self.name}] CDB: {cdb}")

        # Build symbol path from all user-provided paths (; separated for CDB)
        symbol_path = ";".join(p for p in ctx.symbol_paths if p) if ctx.symbol_paths else ""
        if symbol_path:
            print(f"  [{self.name}] 符号路径: {symbol_path}")

        # ── Compute DMP hash for caching ──
        dmp_hash = None
        if self._cache is not None:
            dmp_hash = self._cache.compute_hash(ctx.dump_path)
            cached1 = self._cache.get(dmp_hash, pass_num=1)
            cached2 = self._cache.get(dmp_hash, pass_num=2)
            if cached1 is not None and cached2 is not None:
                print(f"  [{self.name}] 缓存命中，跳过 CDB")
                return self._parse_cached(ctx, cached1, cached2)

        # ── Pass 1: crash analysis with resolved symbols ──
        commands = [".ecxr", "k 30", "~* k", "vertarget", "!analyze -v"]

        print(f"  [{self.name}] Pass 1: 异常上下文 + 调用栈 + 线程 (超时: {self.timeout}s)...")
        raw1 = run_cdb(
            dump_path=ctx.dump_path,
            commands=commands,
            cdb_path=self.cdb_path,
            timeout=self.timeout,
            symbol_path=symbol_path if symbol_path else None,
        )

        # ── Pass 2: module list + heap + locks + address summary ──
        # Multiple memory commands for robustness: !heap -s may return empty,
        # but !address -summary always works regardless of heap state.
        print(f"  [{self.name}] Pass 2: 模块列表 + 堆 + 锁 + 地址空间 ...")
        raw2 = run_cdb(
            dump_path=ctx.dump_path,
            commands=[".reload", "lm", "!heap -s", "!locks", "!address -summary"],
            cdb_path=self.cdb_path,
            timeout=min(self.timeout, 60),
            symbol_path=symbol_path if symbol_path else None,
        )

        # ── Cache CDB output ──
        if self._cache is not None and dmp_hash is not None:
            self._cache.put(dmp_hash, raw1, pass_num=1)
            self._cache.put(dmp_hash, raw2, pass_num=2)

        return self._parse_and_fill(ctx, raw1, raw2)

    def _parse_cached(self, ctx: AnalysisContext, raw1: str, raw2: str
                      ) -> AnalysisContext:
        """Parse cached CDB output and fill context."""
        return self._parse_and_fill(ctx, raw1, raw2)

    def _parse_and_fill(self, ctx: AnalysisContext, raw1: str, raw2: str
                        ) -> AnalysisContext:
        """Parse CDB output and fill AnalysisContext."""
        print(f"  [{self.name}] 解析 CDB 输出 ({len(raw1)}+{len(raw2)} 字节)...")
        ctx.dmp = parse_cdb_output(raw1, ctx.dump_path)

        # Modules/heap/locks/address come from the second pass
        ctx.dmp.modules = parse_module_list(raw2)
        ctx.dmp.heap = parse_heap_info(raw2)
        ctx.dmp.locks = parse_locks(raw2)
        ctx.dmp.address_summary = parse_address_summary(raw2)

        # Memory leak analysis
        from ..memory_analyzer import MemoryLeakAnalyzer
        analyzer = MemoryLeakAnalyzer(ctx.dmp)
        findings = analyzer.analyze()
        ctx.dmp.memory_findings = findings
        if findings:
            ctx.dmp.system_info.memory_pressure_reason = analyzer.pressure_reason(findings)
            # Update virtual memory fields from address summary
            if ctx.dmp.address_summary.get("Free", 0) > 0:
                ctx.dmp.system_info.total_virtual_mb = ctx.dmp.address_summary.get("Free", 0)

        # Post-process: check for local PDB files in ALL symbol paths.
        # CDB's lm output may show (deferred) even when .pdb files exist
        # because .reload doesn't force-load deferred symbols.
        if ctx.symbol_paths:
            from pathlib import Path as _Path
            for mod in ctx.dmp.modules:
                if mod.has_symbols:
                    continue
                pdb_name = _Path(mod.name).stem + ".pdb"
                for sp in ctx.symbol_paths:
                    if (_Path(sp) / pdb_name).is_file():
                        mod.has_symbols = True
                        break

        # Fill in metadata from the parsed data
        ctx.collected_at = ctx.dmp.metadata.timestamp or ""

        print(f"  [{self.name}] 完成: "
              f"异常 {ctx.dmp.exception.name}({ctx.dmp.exception.code}), "
              f"调用栈 {len(ctx.dmp.crash_callstack)} 帧, "
              f"模块 {len(ctx.dmp.modules)}, "
              f"线程 {len(ctx.dmp.all_callstacks)}")

        return ctx
