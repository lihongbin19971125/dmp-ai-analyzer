"""Application log collector.

Searches for log files near the EXE/log directory and extracts entries
near the crash timestamp.  Supports:

- Expanded patterns: .log .txt .csv .json .etl .trace + name-based
- Parent directory search (up to 2 levels above EXE dir)
- Robust timestamp parsing (ISO / CDB / slash / Chinese / epoch)
- Smart error extraction (stack traces, structured JSON errors)
- Deduplication of repeated errors
- Fallback: last N lines when timestamp matching fails
"""

import os
import re
from datetime import datetime, timedelta
from pathlib import Path

from ..context import AnalysisContext, LogInfo
from .base import BaseCollector


class LogCollector(BaseCollector):
    """Collect application log entries near crash time."""

    name = "log_collector"

    # File patterns — extension-based + name-based
    LOG_EXTENSIONS = {".log", ".txt", ".csv", ".json", ".etl", ".trace", ".logging"}
    LOG_NAME_PATTERNS = ["*log*", "*error*", "*debug*", "*trace*", "*crash*", "*dump*"]
    # Extensions to NEVER treat as log files
    _EXCLUDE_EXTENSIONS = {
        ".exe", ".dll", ".sys", ".ocx", ".cpl", ".pdb", ".obj", ".lib",
        ".zip", ".7z", ".rar", ".png", ".jpg", ".ico", ".bmp", ".dmp",
        ".mdmp", ".hdmp",
    }
    # Max depth to walk up from EXE dir searching for logs
    PARENT_SEARCH_DEPTH = 2

    MAX_LOG_LINES = 500
    WINDOW_MINUTES = 5

    def is_applicable(self, ctx: AnalysisContext) -> bool:
        if ctx.log_dir and Path(ctx.log_dir).is_dir():
            return True
        if ctx.exe_dir and Path(ctx.exe_dir).is_dir():
            return True
        return False

    # ------------------------------------------------------------------
    # Collect
    # ------------------------------------------------------------------

    def collect(self, ctx: AnalysisContext) -> AnalysisContext:
        info = LogInfo()
        search_dirs = self._build_search_dirs(ctx)
        print(f"  [{self.name}] 搜索日志文件 ({len(search_dirs)} 个目录)...")

        log_files = self._find_log_files(search_dirs)
        info.files_found = [str(f) for f in log_files]

        if not log_files:
            searched = ", ".join(str(d) for d in search_dirs[:5])
            print(f"  [{self.name}] 未找到日志文件 (已搜索: {searched})")
            ctx.logs = info
            return ctx

        crash_time = self._parse_crash_timestamp(ctx)
        if crash_time:
            print(f"  [{self.name}] 崩溃时间: {crash_time.isoformat()}, "
                  f"窗口: +/-{self.WINDOW_MINUTES} 分钟")
            info.crash_window_logs = self._extract_window(
                log_files, crash_time, self.WINDOW_MINUTES
            )
        else:
            print(f"  [{self.name}] 无法确定崩溃时间, 提取最近日志")
            info.crash_window_logs = self._extract_recent(log_files)

        info.error_summary = self._summarize_errors(info.crash_window_logs)
        ctx.logs = info

        lines = info.crash_window_logs.count("\n") if info.crash_window_logs else 0
        print(f"  [{self.name}] 采集 {len(log_files)} 个日志文件, "
              f"{lines} 行, {len(info.error_summary)} 个错误/警告")
        return ctx

    # ------------------------------------------------------------------
    # Search directory building
    # ------------------------------------------------------------------

    def _build_search_dirs(self, ctx: AnalysisContext) -> list[Path]:
        """Build ordered list of directories to search for log files."""
        dirs: list[Path] = []

        # 1. Explicit log dir
        if ctx.log_dir and Path(ctx.log_dir).is_dir():
            dirs.append(Path(ctx.log_dir).resolve())

        if ctx.exe_dir and Path(ctx.exe_dir).is_dir():
            exe = Path(ctx.exe_dir).resolve()
            dirs.append(exe)
            # Subdirectories: logs, Logs, log, Log, logging
            for sub in ("logs", "Logs", "log", "Log", "logging", "trace", "output"):
                sd = exe / sub
                if sd.is_dir():
                    dirs.append(sd)
            # Parent directories (up to PARENT_SEARCH_DEPTH)
            p = exe.parent
            for _ in range(self.PARENT_SEARCH_DEPTH):
                if p and p.is_dir() and p not in dirs:
                    dirs.append(p)
                if p:
                    p = p.parent
                    if p == p.parent:  # root
                        break

        # 2. Common app-data locations
        for env_var in ("ProgramData", "AppData", "LOCALAPPDATA", "TEMP", "TMP"):
            val = os.environ.get(env_var, "")
            if val and Path(val).is_dir():
                dirs.append(Path(val))

        # Deduplicate preserving order
        seen = set()
        result = []
        for d in dirs:
            key = str(d.resolve())
            if key not in seen:
                seen.add(key)
                result.append(d)
        return result

    # ------------------------------------------------------------------
    # File discovery
    # ------------------------------------------------------------------

    def _find_log_files(self, search_dirs: list[Path]) -> list[Path]:
        """Find log files across all search directories."""
        found: list[Path] = []
        seen = set()

        def _add(fpath: Path) -> None:
            if not fpath.is_file():
                return
            ext = fpath.suffix.lower()
            if ext in self._EXCLUDE_EXTENSIONS:
                return
            key = str(fpath.resolve())
            if key not in seen:
                seen.add(key)
                found.append(fpath)

        for d in search_dirs:
            try:
                # Shallow: iterdir for fast scan
                for entry in d.iterdir():
                    if not entry.is_file():
                        continue
                    name = entry.name.lower()
                    ext = entry.suffix.lower()
                    if ext in self.LOG_EXTENSIONS:
                        _add(entry)
                        continue
                    for pat in self.LOG_NAME_PATTERNS:
                        if self._simple_match(pat, name):
                            _add(entry)
                            break
                # Also try glob for nested log directories (1 level deep)
                for pat in self.LOG_NAME_PATTERNS:
                    for entry in d.glob(pat):
                        _add(entry)
            except PermissionError:
                continue

        found.sort(key=lambda f: f.stat().st_mtime, reverse=True)
        return found[:30]

    @staticmethod
    def _simple_match(pattern: str, name: str) -> bool:
        """Simple glob-like match for * patterns."""
        pat = pattern.lower().replace("*", ".*").replace("?", ".")
        return bool(re.match(f"^{pat}$", name))

    # ------------------------------------------------------------------
    # Timestamp parsing
    # ------------------------------------------------------------------

    def _parse_crash_timestamp(self, ctx: AnalysisContext) -> datetime | None:
        """Parse crash timestamp from DMP metadata."""
        ts = ctx.dmp.metadata.timestamp
        if not ts:
            return None
        ts = ts.strip()

        # Format list: (regex, strptime, extras)
        formats = [
            # ISO 8601
            (r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", "%Y-%m-%dT%H:%M:%S", {}),
            # Slash: 06/28/2026 01:37:54
            (r"^\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}", "%m/%d/%Y %H:%M:%S", {}),
            # Dash: 2026-06-28 01:37:54
            (r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", "%Y-%m-%d %H:%M:%S", {}),
            # CDB: Mon Jun 23 15:26:44.000 2026
            (r"^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",
             "%a %b %d %H:%M:%S.%f %Y", {"default": ".000 2026"}),
            # CDB short: Mon Jun 23 15:26:44 2026
            (r"^[A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4}",
             "%a %b %d %H:%M:%S %Y", {}),
            # Chinese: 2026年6月28日 01:37:54
            (r"^\d{4}年\d{1,2}月\d{1,2}日", "%Y年%m月%d日 %H:%M:%S",
             {"default": " 00:00:00"}),
            # Epoch (10-digit Unix timestamp)
            (r"^\d{10}$", "", {"epoch": True}),
        ]

        ts_clean = ts.strip()[:50]
        for pattern, fmt, extras in formats:
            m = re.match(pattern, ts_clean)
            if not m:
                continue
            if extras.get("epoch"):
                try:
                    return datetime.fromtimestamp(int(ts_clean))
                except (ValueError, OSError):
                    return None
            try:
                matched = m.group(0)
                s = ts_clean[:max(len(matched) + 25, len(fmt) + 8)]
                if "default" in extras:
                    s += " " + extras["default"]
                # Strip trailing noise: everything after a '(' or '（'
                s = re.split(r"[\(（]", s)[0].strip()
                return datetime.strptime(s, fmt)
            except ValueError:
                continue

        # Fallback: extract numbers
        m = re.search(r"(\d{4})[/-](\d{1,2})[/-](\d{1,2})\D+(\d{1,2}):(\d{2}):(\d{2})", ts)
        if m:
            try:
                return datetime(*map(int, m.groups()))
            except ValueError:
                pass
        return None

    # ------------------------------------------------------------------
    # Window extraction
    # ------------------------------------------------------------------

    def _extract_window(
        self, log_files: list[Path], crash_time: datetime, window_minutes: int
    ) -> str:
        """Extract log lines within crash time window with contextual state."""
        window = timedelta(minutes=window_minutes)
        start = crash_time - window
        end = crash_time + window + timedelta(minutes=5)

        lines_out: list[str] = []
        total = 0
        last_in_window = False

        for f in log_files:
            if total >= self.MAX_LOG_LINES:
                break
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                file_lines = content.split("\n")
                if len(file_lines) > 1000:
                    file_lines = file_lines[:300] + file_lines[-700:]
                for line in file_lines:
                    if total >= self.MAX_LOG_LINES:
                        break
                    stripped = line.rstrip()
                    if not stripped:
                        if last_in_window:
                            lines_out.append("")
                        continue
                    match = self._line_in_window(stripped, start, end)
                    if match:
                        last_in_window = True
                        lines_out.append(stripped)
                        total += 1
                    elif last_in_window and not self._has_timestamp(stripped):
                        # Continuation line (e.g. part of a stack trace)
                        lines_out.append(stripped)
                        total += 1
                    else:
                        last_in_window = False
            except (OSError, UnicodeDecodeError):
                continue

        return "\n".join(lines_out)

    def _extract_recent(self, log_files: list[Path]) -> str:
        """Extract most recent log lines (last 200 per file)."""
        lines: list[str] = []
        total = 0
        for f in log_files:
            if total >= self.MAX_LOG_LINES:
                break
            try:
                content = f.read_text(encoding="utf-8", errors="replace")
                file_lines = content.split("\n")
                recent = file_lines[-200:]
                for line in recent:
                    if total >= self.MAX_LOG_LINES:
                        break
                    lines.append(line.rstrip())
                    total += 1
            except (OSError, UnicodeDecodeError):
                continue
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Line matching
    # ------------------------------------------------------------------

    def _line_in_window(
        self, line: str, start: datetime, end: datetime
    ) -> bool:
        """Check if a log line's timestamp falls within the window.

        Returns True if the line has a timestamp in range, or if it has
        no timestamp at all (allowing stack traces / continuation lines
        to be captured by the caller).
        """
        ts_patterns = [
            # ISO with brackets: [2026-06-28T01:37:50]
            (r"[\[(]?(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", "%Y-%m-%dT%H:%M:%S"),
            # ISO space: 2026-06-28 01:37:50
            (r"(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", "%Y-%m-%d %H:%M:%S"),
            # Slash: 06/28/2026 01:37:50
            (r"(\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2})", "%m/%d/%Y %H:%M:%S"),
            # Compact: 06-28 01:37:50
            (r"(\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", "%m-%d %H:%M:%S"),
        ]
        for pat, fmt in ts_patterns:
            m = re.search(pat, line)
            if m:
                try:
                    ts = datetime.strptime(m.group(1), fmt)
                    if fmt == "%m-%d %H:%M:%S":
                        ts = ts.replace(year=start.year)
                    return start <= ts <= end
                except ValueError:
                    continue
        # No timestamp found — return True (allow continuation lines)
        return True

    @staticmethod
    def _has_timestamp(line: str) -> bool:
        """Check if a line contains any recognizable timestamp."""
        return bool(re.search(r"\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}", line))

    # ------------------------------------------------------------------
    # Error extraction
    # ------------------------------------------------------------------

    def _summarize_errors(self, log_text: str) -> list[str]:
        """Extract and deduplicate error/warning/stack-trace lines."""
        if not log_text:
            return []

        # Split into blocks (separated by blank lines or stack trace starters)
        error_lines: list[str] = []
        current_block: list[str] = []
        in_stack_trace = False

        for line in log_text.split("\n"):
            stripped = line.strip()
            if not stripped:
                if current_block:
                    error_lines.append(" | ".join(current_block))
                    current_block = []
                in_stack_trace = False
                continue

            is_error = bool(re.search(
                r"(error|fail|exception|crash|fatal|abort|corrupt|invalid|"
                r"denied|timeout|refused|assert|panic|hang|deadlock|"
                r"null.*reference|access.*violation|out.*of.*memory|"
                r"stack.*overflow|divide.*by.*zero)",
                stripped, re.IGNORECASE
            ))
            is_stack = bool(re.match(r"^\s+(at |\[0x|[A-Za-z_]\w*\!|System\.|"
                                     r"[A-Z]\w+Exception)", stripped))

            if is_stack:
                in_stack_trace = True
                current_block.append(stripped[:200])
            elif is_error or in_stack_trace:
                current_block.append(stripped[:200])
                in_stack_trace = False if is_error else in_stack_trace
            elif current_block:
                error_lines.append(" | ".join(current_block))
                current_block = []

        if current_block:
            error_lines.append(" | ".join(current_block))

        # Deduplicate
        seen = set()
        unique: list[str] = []
        for e in error_lines:
            key = e[:80]
            if key not in seen:
                seen.add(key)
                unique.append(e)

        return unique[:50]
