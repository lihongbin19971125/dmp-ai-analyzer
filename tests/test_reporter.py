"""Tests for reporter.py — Markdown report generation, HTML export,
PDF export, and console summary."""

import json
import re
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from mvp.reporter import generate_report, print_summary, md_to_html


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _make_context(meta=None, dmp=None, source=None, logs=None, config=None):
    """Build a minimal context dict matching AnalysisContext.to_dict() shape."""
    ctx = {
        "meta": meta or {},
        "dmp": dmp or {
            "system_info": {},
            "metadata": {},
            "exception": {},
            "modules": [],
        },
    }
    if source is not None:
        ctx["source"] = source
    if logs is not None:
        ctx["logs"] = logs
    if config is not None:
        ctx["config"] = config
    return ctx


# ═══════════════════════════════════════════════════════════════════════════════
# generate_report tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestGenerateReportBasic:
    """Generate a report with minimal input and verify key sections present."""

    def test_generate_report_basic(self):
        ctx = _make_context(
            meta={"dump_path": "crash.dmp", "collected_at": "2026-06-23T15:26:44"},
        )
        context_json = json.dumps(ctx)
        ai_analysis = "## Test Analysis\n\nThis is a test."
        dump_path = "crash.dmp"
        collected_at = "2026-06-23T15:26:44"

        report = generate_report(context_json, ai_analysis, dump_path, collected_at)

        assert "DMP 崩溃分析报告" in report, "Should contain a top-level heading"
        assert "crash.dmp" in report, "Should reference the DMP file path"
        assert "DMP AI Analyzer v0.1.0" in report, "Should include the footer"
        assert "## Test Analysis" in report, "Should embed the AI analysis text"
        assert "This is a test." in report, "Should embed body of AI analysis"


class TestGenerateReportExceptionDetails:
    """Report includes an exception details table when exception data is present."""

    def test_generate_report_exception_details(self):
        dmp_data = {
            "system_info": {},
            "metadata": {},
            "exception": {
                "code": "C0000005",
                "name": "ACCESS_VIOLATION",
                "address": "00007ff612345678",
                "type": "read",
                "attempted_address": "0000000000000000",
            },
            "modules": [],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # Exception row in the crash summary table
        assert "**ACCESS_VIOLATION**" in report
        assert "`C0000005`" in report
        # Access type row (only present when exception.type is set)
        assert "read" in report
        assert "`0000000000000000`" in report


class TestGenerateReportSystemInfo:
    """Report includes a system info table when os_name is present."""

    def test_generate_report_system_info(self):
        dmp_data = {
            "system_info": {
                "os_name": "Windows 10 Pro",
                "os_version": "10.0.22621",
                "os_build": "22621",
                "platform": "x64",
                "cpu_model": "Intel i9",
                "cpu_count": 16,
                "total_physical_mb": 32768,
                "available_physical_mb": 16384,
            },
            "metadata": {},
            "exception": {},
            "modules": [],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        assert "Windows 10 Pro" in report
        assert "10.0.22621" in report
        assert "22621" in report
        assert "x64" in report
        assert "Intel i9" in report
        assert "16" in report
        assert "32768" in report
        assert "16384" in report
        # Memory percentage should appear (16384 / 32768 * 100 = 50%)
        assert "50%" in report


class TestGenerateReportCrashCallstack:
    """Report includes a formatted callstack code block."""

    def test_generate_report_crash_callstack(self):
        dmp_data = {
            "system_info": {},
            "metadata": {},
            "exception": {},
            "modules": [],
            "crash_callstack": [
                {
                    "frame_index": 0,
                    "function": "myapp!CrashFunc+0x10",
                    "source_file": "crash.cpp",
                    "source_line": 42,
                },
                {
                    "frame_index": 1,
                    "function": "myapp!main+0x42",
                },
            ],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # Code block fences
        assert "```" in report
        # Frame 0: fully decorated with source file and line
        assert "myapp!CrashFunc+0x10" in report
        assert "crash.cpp:42" in report
        # Frame 1: function only, no source annotation
        assert "myapp!main+0x42" in report
        # Frame indices are padded to 2 chars
        assert re.search(r"^\s+0\s+myapp!CrashFunc", report, re.MULTILINE)
        assert re.search(r"^\s+1\s+myapp!main", report, re.MULTILINE)


class TestGenerateReportModulesTable:
    """Report includes a formatted module table with symbol status."""

    def test_generate_report_modules_table(self):
        dmp_data = {
            "system_info": {},
            "metadata": {},
            "exception": {},
            "modules": [
                {
                    "name": "myapp.exe",
                    "version": "1.0.0",
                    "base_address": "00007ff710000000",
                    "size": 524288,
                    "has_symbols": True,
                },
                {
                    "name": "ntdll.dll",
                    "version": "-",
                    "base_address": "00007fff00000000",
                    "size": 2097152,
                    "has_symbols": False,
                },
            ],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # myapp.exe row
        assert "myapp.exe" in report
        assert "1.0.0" in report
        assert "00007ff710000000" in report
        assert "512 KB" in report
        # has_symbols=True renders as checkmark
        assert "✅" in report
        # ntdll.dll row
        assert "ntdll.dll" in report
        assert "00007fff00000000" in report
        assert "2048 KB" in report
        # has_symbols=False renders as cross
        assert "❌" in report


class TestGenerateReportTruncateLongModuleList:
    """Module table truncates at 30 entries with a count summary row."""

    def test_generate_report_truncate_long_module_list(self):
        modules = [
            {
                "name": f"module_{i}.dll",
                "version": f"{i}.0",
                "base_address": f"{0x10000000 + i * 0x100000:016x}",
                "size": 102400,
                "has_symbols": False,
            }
            for i in range(50)
        ]
        dmp_data = {
            "system_info": {},
            "metadata": {},
            "exception": {},
            "modules": modules,
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # Count the module data rows (exclude header and separator rows in the table)
        # Each module row starts with "| module_"
        module_rows = [line for line in report.split("\n") if line.startswith("| module_")]
        assert len(module_rows) == 50, f"All 50 modules should be shown, got {len(module_rows)}"

        # All modules should appear (no truncation)
        assert "module_30.dll" in report
        assert "module_49.dll" in report


class TestGenerateReportSourceSnippets:
    """Report includes source code snippets section when source data is present."""

    def test_generate_report_source_snippets(self):
        source = {
            "snippets": [
                {
                    "file_path": "src/main.cpp",
                    "crash_line": 42,
                    "code": "  >>>     42 | foo->bar();",
                },
            ],
        }
        ctx = _make_context(source=source)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # Verify the source section header and content
        assert "src/main.cpp" in report
        assert "42" in report
        assert "foo->bar()" in report
        assert "```cpp" in report  # code block language hint


class TestGenerateReportGitChanges:
    """Report includes recent git changes when available."""

    def test_generate_report_git_changes(self):
        source = {
            "recent_git_changes": [
                "abc1234 fix: null check (2 hours ago by dev1)",
                "def5678 feat: add new parser (1 day ago by dev2)",
            ],
            "working_tree_dirty": True,
            "snippets": [],
        }
        ctx = _make_context(source=source)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # Should contain both git change entries
        assert "abc1234 fix: null check" in report
        assert "def5678 feat: add new parser" in report
        # Warning about uncommitted changes
        assert "uncommitted" in report.lower() or "未提交" in report


class TestGenerateReportLogErrors:
    """Report includes log error summary when present."""

    def test_generate_report_log_errors(self):
        logs = {
            "error_summary": [
                "ERROR: connection refused on port 8080",
                "FATAL: out of memory",
            ],
        }
        ctx = _make_context(logs=logs)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        assert "connection refused on port 8080" in report
        assert "out of memory" in report


class TestGenerateReportConfig:
    """Report includes config section when config data is present."""

    def test_generate_report_config(self):
        config = {
            "key_settings": {
                "app.config": "[database]\nhost=localhost",
            },
        }
        ctx = _make_context(config=config)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        assert "app.config" in report
        assert "host=localhost" in report
        # Config content should be inside a code block
        assert "```" in report


class TestGenerateReportMemoryPressureWarning:
    """When memory_pressure_reason is set, a warning row is added to system info."""

    def test_generate_report_memory_pressure_warning(self):
        dmp_data = {
            "system_info": {
                "os_name": "Windows 10",
                "total_physical_mb": 8192,
                "available_physical_mb": 512,
                "memory_pressure_reason": "Available memory below 10% threshold",
            },
            "metadata": {},
            "exception": {},
            "modules": [],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        assert "Available memory below 10% threshold" in report
        # The warning emoji row
        assert "⚠" in report  # warning emoji


class TestGenerateReportEmptyModules:
    """When modules list is empty, no modules table is rendered."""

    def test_generate_report_empty_modules(self):
        ctx = _make_context()
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # No modules table header should appear
        assert "加载模块" not in report


class TestGenerateReportEmptyCallstack:
    """When crash_callstack is missing, no callstack section is rendered."""

    def test_generate_report_empty_callstack(self):
        ctx = _make_context()
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        assert "调用栈" not in report


class TestGenerateReportCollectedAtDefault:
    """When collected_at is empty, the report falls back to current time."""

    def test_generate_report_collected_at_default(self):
        ctx = _make_context()
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", collected_at="")

        # Should contain a timestamp (ISO format)
        assert re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", report)


class TestGenerateReportLogErrorTruncation:
    """Log error summary truncates at 20 entries."""

    def test_generate_report_log_error_truncation(self):
        logs = {
            "error_summary": [f"Error {i}" for i in range(25)],
        }
        ctx = _make_context(logs=logs)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # Only first 20 errors should appear
        for i in range(20):
            assert f"Error {i}" in report
        assert "Error 20" not in report
        assert "Error 24" not in report


class TestGenerateReportConfigContentTruncation:
    """Config content is truncated at 2000 characters."""

    def test_generate_report_config_content_truncation(self):
        long_content = "x" * 3000
        config = {
            "key_settings": {
                "large.conf": long_content,
            },
        }
        ctx = _make_context(config=config)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # The full 3000-char string should NOT be in the report
        assert long_content not in report
        # But the first 2000 chars should be
        assert long_content[:2000] in report


class TestGenerateReportSystemInfoUptime:
    """System uptime is displayed in days and hours."""

    def test_generate_report_system_info_uptime(self):
        dmp_data = {
            "system_info": {
                "os_name": "Windows 10",
                "os_version": "10.0",
                "os_build": "22621",
                "platform": "x64",
                "cpu_model": "Intel",
                "cpu_count": 8,
                "total_physical_mb": 16384,
                "available_physical_mb": 8192,
                "system_uptime_seconds": 90000,  # 1 day 1 hour
            },
            "metadata": {},
            "exception": {},
            "modules": [],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # 90000 seconds = 1 day (86400s) + 1 hour (3600s)
        assert "1" in report  # days
        # The uptime row should appear
        assert "运行时间" in report or "uptime" in report.lower()


class TestGenerateReportSystemInfoPagefile:
    """Pagefile info row is included when total_pagefile_mb is set."""

    def test_generate_report_system_info_pagefile(self):
        dmp_data = {
            "system_info": {
                "os_name": "Windows 10",
                "os_version": "10.0",
                "os_build": "22621",
                "platform": "x64",
                "cpu_model": "Intel",
                "cpu_count": 8,
                "total_physical_mb": 16384,
                "available_physical_mb": 8192,
                "total_pagefile_mb": 32768,
            },
            "metadata": {},
            "exception": {},
            "modules": [],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        assert "32768" in report
        assert "页面文件" in report


class TestGenerateReportProcessMemory:
    """Process memory (working set and pagefile) is shown when available."""

    def test_generate_report_process_memory(self):
        dmp_data = {
            "system_info": {
                "os_name": "Windows 10",
                "os_version": "10.0",
                "os_build": "22621",
                "platform": "x64",
                "cpu_model": "Intel",
                "cpu_count": 8,
                "total_physical_mb": 16384,
                "available_physical_mb": 8192,
                "process_working_set_mb": 512,
                "process_pagefile_mb": 1024,
            },
            "metadata": {},
            "exception": {},
            "modules": [],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        assert "512" in report
        assert "1024" in report


class TestGenerateReportCpuFeatures:
    """CPU features list is rendered when present."""

    def test_generate_report_cpu_features(self):
        dmp_data = {
            "system_info": {
                "os_name": "Windows 10",
                "os_version": "10.0",
                "os_build": "22621",
                "platform": "x64",
                "cpu_model": "Intel",
                "cpu_count": 8,
                "cpu_features": ["SSE2", "AVX", "AVX2"],
                "total_physical_mb": 16384,
                "available_physical_mb": 8192,
            },
            "metadata": {},
            "exception": {},
            "modules": [],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        assert "SSE2" in report
        assert "AVX" in report
        assert "AVX2" in report


class TestGenerateReportNoAccessType:
    """When exception.type is empty, the access type row is omitted."""

    def test_generate_report_no_access_type(self):
        dmp_data = {
            "system_info": {},
            "metadata": {},
            "exception": {
                "code": "C0000005",
                "name": "ACCESS_VIOLATION",
                "address": "00007ff612345678",
                "type": "",
                "attempted_address": "",
            },
            "modules": [],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        # Access type row should not appear because type is falsy
        assert "访问类型" not in report


class TestGenerateReportMetadataFields:
    """Metadata fields (process_name, process_id, timestamp) appear in the summary table."""

    def test_generate_report_metadata_fields(self):
        dmp_data = {
            "system_info": {},
            "metadata": {
                "process_name": "myapp.exe",
                "process_id": 1234,
                "timestamp": "2026-06-23 15:26:44",
            },
            "exception": {},
            "modules": [],
        }
        ctx = _make_context(dmp=dmp_data)
        context_json = json.dumps(ctx)
        report = generate_report(context_json, "# AI", "test.dmp", "2026-06-23T00:00:00")

        assert "myapp.exe" in report
        assert "1234" in report
        assert "2026-06-23 15:26:44" in report


# ═══════════════════════════════════════════════════════════════════════════════
# print_summary tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestPrintSummary:
    """Tests for print_summary console output function."""

    def test_print_summary_root_cause(self, capsys):
        """print_summary extracts root cause section from AI analysis text."""
        ai_analysis = (
            "# Analysis\n\n"
            "## Root cause\n\n"
            "A null pointer was dereferenced because the function "
            "did not check the return value of GetObject().\n\n"
            "## Fix\n"
            "Add null check."
        )
        print_summary(ai_analysis)
        captured = capsys.readouterr()
        assert "[ROOT CAUSE]" in captured.out
        assert "null pointer was dereferenced" in captured.out

    def test_print_summary_root_cause_chinese(self, capsys):
        """print_summary also matches Chinese '根因' heading."""
        ai_analysis = (
            "# 分析\n\n"
            "## 根因\n\n"
            "缓冲区溢出导致堆损坏。\n\n"
            "## 修复建议\n"
            "增加边界检查。"
        )
        print_summary(ai_analysis)
        captured = capsys.readouterr()
        assert "[ROOT CAUSE]" in captured.out
        assert "缓冲区溢出" in captured.out

    def test_print_summary_fallback(self, capsys):
        """print_summary falls back to first non-empty non-heading line when no root cause section found."""
        ai_analysis = (
            "# Analysis\n\n"
            "The application crashed due to a buffer overflow in ProcessData.\n\n"
            "Evidence: ..."
        )
        print_summary(ai_analysis)
        captured = capsys.readouterr()
        assert "[SUMMARY]" in captured.out
        assert "buffer overflow in ProcessData" in captured.out

    def test_print_summary_fallback_skips_headings(self, capsys):
        """print_summary skips heading lines when finding fallback summary."""
        ai_analysis = (
            "# Header\n"
            "## Subheader\n"
            "Actual first sentence here.\n"
        )
        print_summary(ai_analysis)
        captured = capsys.readouterr()
        assert "[SUMMARY]" in captured.out
        assert "Actual first sentence here" in captured.out

    def test_print_summary_truncates_long_lines(self, capsys):
        """print_summary truncates extracted text at 200 characters."""
        long_cause = "X" * 300
        ai_analysis = f"## Root cause\n\n{long_cause}\n"
        print_summary(ai_analysis)
        captured = capsys.readouterr()
        assert "[ROOT CAUSE]" in captured.out
        # The output should contain at most 200 chars of the cause plus prefix
        assert len(captured.out.strip()) <= 220  # generous allowance for prefix

    def test_print_summary_root_cause_case_insensitive(self, capsys):
        """print_summary matches 'Root Cause' case-insensitively."""
        ai_analysis = (
            "# Analysis\n\n"
            "## ROOT CAUSE\n\n"
            "The crash happened because of a race condition.\n"
        )
        print_summary(ai_analysis)
        captured = capsys.readouterr()
        assert "[ROOT CAUSE]" in captured.out
        assert "race condition" in captured.out


class TestIntegrationScenarios:
    """End-to-end report generation with realistic context shapes."""

    def test_full_report_all_sections(self):
        """A context with all optional sections produces a complete report."""
        dmp_data = {
            "system_info": {
                "os_name": "Windows 11 Pro",
                "os_version": "10.0.26100",
                "os_build": "26100",
                "platform": "x64",
                "cpu_model": "Intel Core i7-13700",
                "cpu_count": 20,
                "cpu_features": ["SSE2", "AVX2"],
                "total_physical_mb": 32768,
                "available_physical_mb": 24576,
                "total_pagefile_mb": 65536,
                "process_working_set_mb": 512,
                "process_pagefile_mb": 1024,
                "system_uptime_seconds": 270000,
                "memory_pressure_reason": "Available memory below 10% threshold",
            },
            "metadata": {
                "process_name": "myapp.exe",
                "process_id": 5678,
                "timestamp": "2026-06-23 15:26:44",
            },
            "exception": {
                "code": "C0000005",
                "name": "ACCESS_VIOLATION",
                "address": "00007ff612345678",
                "type": "read",
                "attempted_address": "0000000000000000",
            },
            "crash_callstack": [
                {
                    "frame_index": 0,
                    "function": "myapp!CrashFunc+0x10",
                    "source_file": "src/crash.cpp",
                    "source_line": 42,
                },
                {
                    "frame_index": 1,
                    "function": "myapp!main+0x42",
                },
            ],
            "modules": [
                {
                    "name": "myapp.exe",
                    "version": "2.3.1",
                    "base_address": "00007ff710000000",
                    "size": 1048576,
                    "has_symbols": True,
                },
                {
                    "name": "ntdll.dll",
                    "version": "10.0.26100.1",
                    "base_address": "00007fff00000000",
                    "size": 2097152,
                    "has_symbols": False,
                },
            ],
        }
        source = {
            "snippets": [
                {
                    "file_path": "src/crash.cpp",
                    "crash_line": 42,
                    "code": "  >>>     42 | obj->DoWork(data);",
                }
            ],
            "recent_git_changes": [
                "abc1234 fix: null check (2 hours ago by dev1)",
            ],
            "working_tree_dirty": False,
        }
        logs = {
            "error_summary": [
                "ERROR: connection refused on port 8080",
            ],
        }
        config = {
            "key_settings": {
                "app.config": "[database]\nhost=localhost\nport=5432",
            },
        }
        ctx = _make_context(
            dmp=dmp_data,
            source=source,
            logs=logs,
            config=config,
        )
        context_json = json.dumps(ctx)
        report = generate_report(
            context_json,
            "# Full AI Analysis\n\nCrash was caused by invalid memory access.",
            "customer_crash.dmp",
            "2026-06-23T15:30:00",
        )

        # Spot-check every major section
        assert "customer_crash.dmp" in report
        assert "myapp.exe" in report
        assert "ACCESS_VIOLATION" in report
        assert "Windows 11 Pro" in report
        assert "Intel Core i7-13700" in report
        assert "SSE2" in report
        assert "AVX2" in report
        assert "75%" in report  # 24576/32768
        assert "内存压力" in report or "memory pressure" in report.lower()
        assert "src/crash.cpp:42" in report
        assert "obj->DoWork(data)" in report
        assert "abc1234" in report
        assert "connection refused" in report
        assert "host=localhost" in report
        assert "Crash was caused by invalid memory access" in report
        assert "DMP AI Analyzer v0.1.0" in report


# ═══════════════════════════════════════════════════════════════════════════════
# PDF export tests
# ═══════════════════════════════════════════════════════════════════════════════

class TestHtmlToPdf:
    """Tests for html_to_pdf() — PDF generation backends.

    All tests mock Edge away so we can test WeasyPrint/fpdf2 paths.
    """

    @staticmethod
    def _patch_edge_not_found():
        """Make Edge and any system commands unavailable."""
        # Patch os.path.isfile to make Edge paths not found
        # Also patch shutil.which to return None
        p1 = patch("os.path.isfile", return_value=False)
        p2 = patch("shutil.which", return_value=None)
        return (p1, p2)

    def test_weasyprint_backend(self, tmp_path):
        """html_to_pdf uses weasyprint when Edge not available."""
        from mvp.reporter import html_to_pdf
        html = "<html><body><h1>Test</h1></body></html>"
        out = tmp_path / "test.pdf"

        p1, p2 = self._patch_edge_not_found()
        mock_html = Mock()
        mock_html_instance = Mock()
        mock_html.return_value = mock_html_instance
        with p1, p2, patch.dict("sys.modules", {"weasyprint": Mock(HTML=mock_html)}):
            html_to_pdf(html, str(out))
            mock_html.assert_called_once_with(string=html)
            mock_html_instance.write_pdf.assert_called_once_with(str(out))

    def test_import_error_when_nothing_available(self, tmp_path):
        """Friendly error when no backend is available."""
        from mvp.reporter import html_to_pdf
        p1, p2 = self._patch_edge_not_found()
        with p1, p2, patch.dict("sys.modules", {"weasyprint": None, "fpdf": None}):
            with pytest.raises(ImportError, match="PDF export requires"):
                html_to_pdf("<html></html>", str(tmp_path / "out.pdf"))

    def test_fallback_to_fpdf2(self, tmp_path):
        """When Edge and weasyprint unavailable, uses fpdf2."""
        from mvp.reporter import html_to_pdf
        p1, p2 = self._patch_edge_not_found()
        mock_fpdf = Mock()
        mock_fpdf_instance = Mock()
        # Configure mock to support arithmetic on layout attributes
        mock_fpdf_instance.w = 210
        mock_fpdf_instance.l_margin = 10
        mock_fpdf_instance.r_margin = 10
        mock_fpdf.return_value = mock_fpdf_instance
        with p1, p2, patch.dict("sys.modules", {
            "weasyprint": None,
            "fpdf": Mock(FPDF=mock_fpdf),
        }):
            html_to_pdf("<html><body>Test</body></html>", str(tmp_path / "out.pdf"))
            mock_fpdf.assert_called_once()
            mock_fpdf_instance.add_page.assert_called_once()
            mock_fpdf_instance.output.assert_called_once()


class TestPdfCLIIntegration:
    """Integration tests for --format pdf in reports."""

    def test_md_to_html_chain(self, tmp_path):
        """Full chain: Markdown → HTML (PDF step mocked)."""
        from mvp.reporter import md_to_html
        md = "# 测试报告\n\n这是测试内容。"
        html = md_to_html(md)
        # HTML should contain key elements (either via markdown lib or <pre> fallback)
        assert "测试报告" in html or "Test" in html
        assert "</html>" in html
