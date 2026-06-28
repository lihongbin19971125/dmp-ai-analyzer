"""Configuration file collector.

Searches for config files near the EXE directory, reads them,
and sanitizes sensitive values.
"""

import os
import re
from pathlib import Path

from ..context import AnalysisContext, ConfigInfo
from .base import BaseCollector


class ConfigCollector(BaseCollector):
    """Collect application configuration (sanitized)."""

    name = "config_collector"

    CONFIG_EXTENSIONS = {".config", ".xml", ".json", ".ini", ".yaml",
                         ".yml", ".cfg", ".conf", ".toml"}

    # Patterns for sensitive values to redact
    SENSITIVE_KEYS = re.compile(
        r"(password|passwd|secret|key|token|apikey|api_key|"
        r"connectionstring|private_key|credential)",
        re.IGNORECASE
    )

    MAX_CONFIG_SIZE = 64 * 1024  # 64 KB per file
    MAX_FILES = 20
    MAX_LINE_LENGTH = 200

    def is_applicable(self, ctx: AnalysisContext) -> bool:
        return bool(ctx.exe_dir) and Path(ctx.exe_dir).is_dir()

    def collect(self, ctx: AnalysisContext) -> AnalysisContext:
        exe_dir = Path(ctx.exe_dir).resolve()
        info = ConfigInfo()
        print(f"  [{self.name}] 搜索配置文件: {exe_dir}")

        config_files = self._find_config_files(exe_dir)
        info.config_files = [str(f) for f in config_files]

        for cf in config_files:
            content = self._read_and_sanitize(cf)
            if content:
                info.key_settings[str(cf.relative_to(exe_dir))] = content

        ctx.config = info
        print(f"  [{self.name}] 找到 {len(config_files)} 个配置文件")
        return ctx

    # ------------------------------------------------------------------

    def _find_config_files(self, exe_dir: Path) -> list[Path]:
        """Find configuration files near the EXE."""
        found = []
        seen = set()

        # Search root and 1 level deep
        search_roots = [exe_dir] + [
            d for d in exe_dir.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        ]
        for root in search_roots:
            try:
                for entry in root.iterdir():
                    if entry.is_file() and entry.suffix.lower() in self.CONFIG_EXTENSIONS:
                        key = str(entry.resolve())
                        if key not in seen and len(found) < self.MAX_FILES:
                            seen.add(key)
                            found.append(entry)
            except PermissionError:
                continue

        return found

    def _read_and_sanitize(self, path: Path) -> str:
        """Read a config file, truncate if large, and redact sensitive values."""
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeDecodeError):
            return ""

        if len(content) > self.MAX_CONFIG_SIZE:
            content = content[:self.MAX_CONFIG_SIZE // 2] + "\n... [truncated]\n" + content[-self.MAX_CONFIG_SIZE // 2:]

        # Sanitize each line
        lines = []
        for line in content.split("\n"):
            line = line.strip()
            if not line:
                continue
            # Truncate long lines
            if len(line) > self.MAX_LINE_LENGTH:
                line = line[:self.MAX_LINE_LENGTH] + "..."
            # Redact sensitive values
            if self.SENSITIVE_KEYS.search(line):
                line = self._redact_line(line)
            lines.append(line)

        return "\n".join(lines[:100])  # Max 100 lines per file

    def _redact_line(self, line: str) -> str:
        """Replace sensitive values with ***."""
        # key=value or key: value patterns
        line = re.sub(
            r'(=)\s*(\S+)',
            r'\1 ***',
            line
        )
        line = re.sub(
            r'(:)\s*(\S+)',
            r'\1 ***',
            line
        )
        return line
