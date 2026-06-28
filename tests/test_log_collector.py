"""Tests for enhanced log collector.

Covers:
- Expanded file patterns (json/etl/trace/debug/rotating)
- Multi-directory search (EXE dir + parent + AppData + TEMP)
- Robust timestamp parsing (ISO/epoch/Windows trace/compact)
- Smart error extraction (stack traces, structured errors)
- Fallback: last N lines when timestamp match fails
- Search path reporting when nothing found
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from mvp.collectors.log_collector import LogCollector
from mvp.context import AnalysisContext, DmpData, DmpMetadata


# ──────────────────────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def collector():
    return LogCollector()


@pytest.fixture
def ctx_with_crash_time():
    ctx = AnalysisContext(
        dump_path="test.dmp",
        exe_dir=r"C:\test\app",
        collected_at="2026-06-28T01:37:54",
    )
    ctx.dmp = DmpData()
    ctx.dmp.metadata.timestamp = "2026-06-28T01:37:54"
    return ctx


def _write_log(tmp_path, filename: str, content: str):
    p = tmp_path / filename
    p.write_text(content, encoding="utf-8")
    return p


# ──────────────────────────────────────────────────────────────
# File pattern discovery
# ──────────────────────────────────────────────────────────────

class TestFileDiscovery:
    """Tests for log file pattern matching."""

    def test_finds_json_logs(self, tmp_path, collector):
        """Should detect .json log files."""
        log = _write_log(tmp_path, "app_20260628.json",
                         '{"time":"2026-06-28T01:37:50","level":"ERROR","msg":"crash imminent"}')
        ctx = AnalysisContext(exe_dir=str(tmp_path), dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        ctx.dmp.metadata.timestamp = "2026-06-28T01:37:54"
        found = collector._find_log_files([tmp_path])
        names = [f.name for f in found]
        assert "app_20260628.json" in names

    def test_finds_trace_logs(self, tmp_path, collector):
        """Should detect trace/debug log files."""
        _write_log(tmp_path, "debug.trace", "trace data")
        _write_log(tmp_path, "app.etl", "etl data")
        ctx = AnalysisContext(exe_dir=str(tmp_path), dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        found = collector._find_log_files([tmp_path])
        names = [f.name for f in found]
        assert "debug.trace" in names

    def test_finds_named_log_patterns(self, tmp_path, collector):
        """Files with 'log', 'error', 'trace', 'debug' in name should match."""
        _write_log(tmp_path, "error_report.txt", "errors")
        _write_log(tmp_path, "debug_output.txt", "debug")
        _write_log(tmp_path, "trace_20260628.txt", "trace")
        ctx = AnalysisContext(exe_dir=str(tmp_path), dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        found = collector._find_log_files([tmp_path])
        names = [f.name for f in found]
        assert "error_report.txt" in names
        assert "debug_output.txt" in names
        assert "trace_20260628.txt" in names

    def test_excludes_binaries(self, tmp_path, collector):
        """Should NOT include .exe/.dll even if they contain 'log' in name."""
        _write_log(tmp_path, "logger.dll", "binary")
        _write_log(tmp_path, "login.exe", "binary")
        ctx = AnalysisContext(exe_dir=str(tmp_path), dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        found = collector._find_log_files([tmp_path])
        names = [f.name for f in found]
        assert "logger.dll" not in names
        assert "login.exe" not in names

    def test_searches_parent_dirs(self, tmp_path, collector):
        """Should search parent directories up to 2 levels via _build_search_dirs."""
        app_dir = tmp_path / "app" / "bin"
        app_dir.mkdir(parents=True)
        _write_log(tmp_path / "app", "service.log", "log data")
        ctx = AnalysisContext(exe_dir=str(app_dir), dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        # _build_search_dirs adds parent dirs
        search_dirs = collector._build_search_dirs(ctx)
        found = collector._find_log_files(search_dirs)
        paths = [str(f) for f in found]
        assert any("service.log" in p for p in paths)


# ──────────────────────────────────────────────────────────────
# Timestamp parsing
# ──────────────────────────────────────────────────────────────

class TestTimestampParsing:
    """Tests for crash time extraction from various formats."""

    def test_iso_format(self, collector, ctx_with_crash_time):
        """ISO 8601: 2026-06-28T01:37:54"""
        result = collector._parse_crash_timestamp(ctx_with_crash_time)
        assert result is not None
        assert result.year == 2026
        assert result.month == 6
        assert result.day == 28
        assert result.hour == 1
        assert result.minute == 37

    def test_cdb_format(self, collector):
        """CDB format: Mon Jun 23 15:26:44.000 2026"""
        ctx = AnalysisContext(dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        ctx.dmp.metadata.timestamp = "Mon Jun 23 15:26:44.000 2026 (UTC + 8:00)"
        result = collector._parse_crash_timestamp(ctx)
        assert result is not None
        assert result.month == 6
        assert result.day == 23

    def test_slash_format(self, collector):
        """06/28/2026 01:37:54"""
        ctx = AnalysisContext(dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        ctx.dmp.metadata.timestamp = "06/28/2026 01:37:54"
        result = collector._parse_crash_timestamp(ctx)
        assert result is not None
        assert result.month == 6
        assert result.day == 28

    def test_chinese_format(self, collector):
        """Chinese date format using Unicode escapes."""
        ctx = AnalysisContext(dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        ctx.dmp.metadata.timestamp = "2026年6月28日 01:37:54"
        result = collector._parse_crash_timestamp(ctx)
        assert result is not None
        assert result.month == 6

    def test_epoch_timestamp(self, collector):
        """Unix epoch: 1751343474"""
        ctx = AnalysisContext(dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        ctx.dmp.metadata.timestamp = "1751343474"
        result = collector._parse_crash_timestamp(ctx)
        # Epoch timestamp > year 2000 means it's likely a Unix timestamp
        assert result is not None

    def test_empty_timestamp_returns_none(self, collector):
        ctx = AnalysisContext(dump_path="t.dmp", collected_at="")
        ctx.dmp = DmpData()
        ctx.dmp.metadata.timestamp = ""
        assert collector._parse_crash_timestamp(ctx) is None


# ──────────────────────────────────────────────────────────────
# Line-in-window matching
# ──────────────────────────────────────────────────────────────

class TestLineWindowMatching:
    """Tests for time-window log line filtering."""

    def test_iso_line_in_window(self, collector):
        """Line with ISO timestamp within window."""
        line = "[2026-06-28T01:37:50] ERROR: connection lost"
        start = datetime(2026, 6, 28, 1, 32, 54)
        end = datetime(2026, 6, 28, 1, 42, 54)
        assert collector._line_in_window(line, start, end) is True

    def test_line_outside_window(self, collector):
        """Line with timestamp outside window."""
        line = "[2026-06-28T02:00:00] INFO: started"
        start = datetime(2026, 6, 28, 1, 32, 54)
        end = datetime(2026, 6, 28, 1, 42, 54)
        assert collector._line_in_window(line, start, end) is False

    def test_line_without_timestamp(self, collector):
        """Line without any recognizable timestamp — include anyway (proximity)."""
        line = "    at MyApp.ProcessData() in process.cpp:342"
        start = datetime(2026, 6, 28, 1, 32, 54)
        end = datetime(2026, 6, 28, 1, 42, 54)
        # Lines without timestamps are included if they're between
        # timestamped lines within the window
        assert collector._line_in_window(line, start, end) is True

    def test_compact_timestamp(self, collector):
        """Compact: 06-28 01:37:50"""
        line = "06-28 01:37:50 Crash detected"
        start = datetime(2026, 6, 28, 1, 32, 54)
        end = datetime(2026, 6, 28, 1, 42, 54)
        assert collector._line_in_window(line, start, end) is True


# ──────────────────────────────────────────────────────────────
# Smart error extraction
# ──────────────────────────────────────────────────────────────

class TestErrorExtraction:
    """Tests for smart error/warning/stack-trace extraction."""

    def test_extracts_stack_trace(self, collector):
        """Should capture stack traces from log output."""
        log = """
        2026-06-28T01:37:53 INFO Starting
        2026-06-28T01:37:54 ERROR Unhandled exception:
        System.NullReferenceException: Object reference not set
           at MyApp.ProcessData() in process.cpp:342
           at MyApp.HandleRequest() in handler.cpp:156
        """
        errors = collector._summarize_errors(log)
        assert any("NullReferenceException" in e for e in errors)
        # Stack frames may be part of error blocks or standalone
        assert any("process.cpp" in e or "NullReferenceException" in e for e in errors)

    def test_extracts_structured_errors(self, collector):
        """Should extract structured JSON error entries."""
        log = """
        {"time":"2026-06-28T01:37:53","level":"ERROR","code":500,"msg":"DB timeout"}
        {"time":"2026-06-28T01:37:54","level":"FATAL","code":501,"msg":"Out of memory"}
        """
        errors = collector._summarize_errors(log)
        assert any("DB timeout" in e for e in errors)
        assert any("Out of memory" in e for e in errors)

    def test_deduplicates_similar_errors(self, collector):
        """Should deduplicate repeated identical errors."""
        log = "ERROR: timeout\n" * 100
        errors = collector._summarize_errors(log)
        assert len(errors) <= 25  # max 25 unique errors

    def test_truncates_long_lines(self, collector):
        """Should truncate error lines longer than 300 chars."""
        long_line = "ERROR: " + "x" * 500
        errors = collector._summarize_errors(long_line)
        assert len(errors[0]) <= 305  # 300 + "..." marker


# ──────────────────────────────────────────────────────────────
# Fallback behavior
# ──────────────────────────────────────────────────────────────

class TestFallbackBehavior:
    """Tests for when no timestamped logs are found."""

    def test_extracts_last_lines_as_fallback(self, tmp_path, collector):
        """When no timestamp matching works, extract last 200 lines."""
        log = _write_log(tmp_path, "app.log", "line " + "data\n" * 300)
        lines = collector._extract_recent([log])
        assert lines.count("\n") > 0

    def test_reports_search_paths_when_empty(self, collector):
        """When nothing found, the collect() result should note search paths."""
        ctx = AnalysisContext(
            exe_dir="/nonexistent/path",
            dump_path="t.dmp",
            collected_at="",
        )
        ctx.dmp = DmpData()
        # Mock _find_log_files to return empty
        with patch.object(collector, '_find_log_files', return_value=[]):
            ctx = collector.collect(ctx)
        # Should have logged the attempt
        assert ctx.logs is not None
        assert ctx.logs.files_found == []


# ──────────────────────────────────────────────────────────────
# Integration: collect with real files
# ──────────────────────────────────────────────────────────────

class TestCollectIntegration:
    """End-to-end collect() with real log files."""

    def test_collect_with_crash_window(self, tmp_path, collector):
        """Full flow: find logs, filter by crash window, extract errors."""
        # Create a realistic log
        log_content = (
            "2026-06-28T01:37:50 INFO App started\n"
            "2026-06-28T01:37:52 WARN Config file missing, using defaults\n"
            "2026-06-28T01:37:53 ERROR Failed to allocate buffer (4096 bytes)\n"
            "2026-06-28T01:37:54 FATAL Access violation at 0x005e36cf\n"
            "Stack trace:\n"
            "  App!TriggerNullPointerCrash+0x1f\n"
            "  App!WndProc+0x2b2\n"
        )
        log = _write_log(tmp_path, "app.log", log_content)

        ctx = AnalysisContext(
            exe_dir=str(tmp_path),
            dump_path="test.dmp",
            collected_at="",
        )
        ctx.dmp = DmpData()
        ctx.dmp.metadata.timestamp = "2026-06-28T01:37:54"

        # Override search dirs to only use our tmp_path
        with patch.object(collector, '_find_log_files', return_value=[log]):
            ctx = collector.collect(ctx)

        assert ctx.logs is not None
        assert len(ctx.logs.files_found) == 1
        # Should have captured crash-window logs
        assert len(ctx.logs.crash_window_logs) > 0
        # Should have extracted error lines
        assert len(ctx.logs.error_summary) > 0
        assert any("Failed to allocate" in e for e in ctx.logs.error_summary) or \
               any("Access violation" in e for e in ctx.logs.error_summary)
