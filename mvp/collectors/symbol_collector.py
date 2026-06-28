"""Symbol file collector.

Searches all user-provided symbol paths for .pdb files matching
the loaded modules and reports symbol availability.
"""

import os
from pathlib import Path

from ..context import AnalysisContext, SymbolInfo
from .base import BaseCollector


class SymbolCollector(BaseCollector):
    """Check symbol availability across all symbol paths."""

    name = "symbol_collector"

    def is_applicable(self, ctx: AnalysisContext) -> bool:
        return bool(ctx.symbol_paths) and len(ctx.dmp.modules) > 0

    def collect(self, ctx: AnalysisContext) -> AnalysisContext:
        info = SymbolInfo()

        # Build a PDB index across all symbol paths
        pdb_map: dict[str, Path] = {}
        for sp in ctx.symbol_paths:
            p = Path(sp).resolve()
            if not p.is_dir():
                continue
            print(f"  [{self.name}] 搜索: {p}")
            for root, _, files in os.walk(p):
                for f in files:
                    if f.lower().endswith(".pdb"):
                        key = f.lower()
                        if key not in pdb_map:  # first path wins
                            pdb_map[key] = Path(root) / f

        if not pdb_map:
            print(f"  [{self.name}] 未找到任何 PDB 文件")
            ctx.symbols = info
            return ctx

        for mod in ctx.dmp.modules:
            mod_stem = Path(mod.name).stem.lower()
            pdb_name = f"{mod_stem}.pdb"

            if pdb_name in pdb_map:
                info.module_symbols[mod.name] = f"found: {pdb_map[pdb_name]}"
            elif mod.has_symbols:
                info.module_symbols[mod.name] = "loaded"
            else:
                info.module_symbols[mod.name] = "missing"

        ctx.symbols = info
        found = sum(1 for v in info.module_symbols.values()
                    if v.startswith("found") or v == "loaded")
        total = len(info.module_symbols)
        print(f"  [{self.name}] 符号状态: {found}/{total} 可用 ({len(pdb_map)} 个 PDB 文件)")
        return ctx
