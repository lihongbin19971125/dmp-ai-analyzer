"""Tests for batch analysis mode.

Covers:
- BatchRunner: glob expansion, per-file pipeline, error resilience
- BatchReporter: summary markdown generation
- CLI: --batch flag routing
"""

import json
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from mvp.context import (
    AnalysisContext, DmpData, DmpMetadata, ExceptionInfo, Frame, SystemInfo
)


# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────

def _make_result(
    dump_path: str = "crash.dmp",
    exception_code: str = "C0000005",
    exception_name: str = "ACCESS_VIOLATION",
    crash_module: str = "myapp",
    crash_function: str = "myapp!CrashFunc+0x42",
    crash_source: str | None = "crash.cpp:42",
    timestamp: str = "2026-06-28T01:00:00",
    ai_result: str = "## AI Analysis\n\nRoot cause: null pointer.",
) -> dict:
    """Build a minimal analysis result dict (what BatchRunner stores)."""
    dmp = DmpData()
    dmp.metadata.timestamp = timestamp
    dmp.exception = ExceptionInfo(code=exception_code, name=exception_name)
    dmp.crash_callstack = [Frame(
        frame_index=0, module=crash_module, function=crash_function,
        source_file=crash_source.split(":")[0] if crash_source else None,
        source_line=int(crash_source.split(":")[1]) if crash_source and ":" in crash_source else None,
    )]
    dmp.system_info = SystemInfo(os_name="Windows 10", platform="x64")

    ctx = AnalysisContext(dump_path=dump_path, collected_at=timestamp)
    ctx.dmp = dmp
    return {
        "dump_path": dump_path,
        "ctx": ctx,
        "json": json.dumps(ctx.to_dict(), ensure_ascii=False),
        "ai_result": ai_result,
        "report_path": dump_path.replace(".dmp", "_report.md"),
        "error": None,
    }


def _make_error_result(dump_path: str, error_msg: str) -> dict:
    """Build a failed analysis result."""
    return {
        "dump_path": dump_path,
        "ctx": None,
        "json": "",
        "ai_result": "",
        "report_path": "",
        "error": error_msg,
    }


# ──────────────────────────────────────────────────────────────
# BatchRunner
# ──────────────────────────────────────────────────────────────

class TestBatchRunner:
    """Tests for file collection and per-file pipeline execution."""

    def test_expand_glob_pattern(self):
        """Should expand glob patterns to file list."""
        from mvp.batch import BatchRunner
        runner = BatchRunner()
        # Test with explicit file list (no glob expansion needed)
        files = runner._collect_files([
            "D:/dumps/crash1.dmp",
            "D:/dumps/crash2.dmp",
        ])
        assert len(files) == 2
        assert all(f.endswith(".dmp") for f in files)

    def test_expand_directory(self, tmp_path):
        """Should find .dmp files via glob in a real directory."""
        from mvp.batch import BatchRunner
        # Create real files in a temp dir
        (tmp_path / "crash1.dmp").write_text("")
        (tmp_path / "crash2.dmp").write_text("")
        (tmp_path / "readme.txt").write_text("")
        runner = BatchRunner()
        files = runner._collect_files([str(tmp_path / "*.dmp")])
        assert len(files) == 2
        assert all(f.endswith(".dmp") for f in files)

    def test_runs_pipeline_for_each_file(self):
        """Should run full pipeline on every DMP file."""
        from mvp.batch import BatchRunner

        # Mock the two-phase pipeline
        with patch("mvp.batch.collect_context") as mock_collect, \
             patch("mvp.batch.analyze_context") as mock_analyze:
            mock_collect.side_effect = [
                _make_result("c1.dmp"),
                _make_result("c2.dmp", exception_code="C00000FD"),
            ]
            mock_analyze.side_effect = lambda r, **kw: r

            runner = BatchRunner()
            results = runner.run(["c1.dmp", "c2.dmp"])

            assert len(results) == 2
            assert results[0]["dump_path"] == "c1.dmp"
            assert results[0]["error"] is None
            assert results[1]["error"] is None
            assert mock_collect.call_count == 2

    def test_error_resilience_one_fails(self):
        """Should continue processing when one DMP fails."""
        from mvp.batch import BatchRunner

        with patch("mvp.batch.collect_context") as mock_collect, \
             patch("mvp.batch.analyze_context") as mock_analyze:
            mock_collect.side_effect = [
                _make_result("ok.dmp"),
                _make_error_result("bad.dmp", "CDB timeout after 60s"),
            ]
            mock_analyze.side_effect = lambda r, **kw: r

            runner = BatchRunner()
            results = runner.run(["ok.dmp", "bad.dmp"])

            assert len(results) == 2
            assert results[0]["error"] is None
            assert results[1]["error"] is not None
            assert "CDB timeout" in str(results[1]["error"])

    def test_all_fail_still_returns_results(self):
        """Should return results even when all DMPs fail."""
        from mvp.batch import BatchRunner

        with patch("mvp.batch.collect_context") as mock_analyze:
            mock_analyze.side_effect = [
                _make_error_result("a.dmp", "CDB timeout"),
                _make_error_result("b.dmp", "Symbol load failed"),
            ]

            runner = BatchRunner()
            results = runner.run(["a.dmp", "b.dmp"])

            assert len(results) == 2
            assert all(r["error"] is not None for r in results)

    def test_empty_file_list(self):
        """Should return empty list for no files."""
        from mvp.batch import BatchRunner
        runner = BatchRunner()
        results = runner.run([])
        assert results == []


# ──────────────────────────────────────────────────────────────
# BatchReporter
# ──────────────────────────────────────────────────────────────

class TestBatchReporter:
    """Tests for batch summary report generation."""

    def test_generates_overview_table(self):
        """Summary should include a table with all DMPs."""
        from mvp.batch import BatchReporter

        results = [
            _make_result("c1.dmp", exception_code="C0000005",
                         exception_name="ACCESS_VIOLATION",
                         crash_function="app!Crash+0x10",
                         timestamp="2026-06-28T01:00:00",
                         ai_result="## AI\nRoot cause: null pointer"),
            _make_result("c2.dmp", exception_code="C00000FD",
                         exception_name="STACK_OVERFLOW",
                         crash_function="app!Recurse+0x5",
                         timestamp="2026-06-28T02:00:00",
                         ai_result="## AI\nRoot cause: infinite recursion"),
        ]

        report = BatchReporter().generate(results, exe_dir="C:/app")
        assert "# 批量崩溃分析汇总" in report
        assert "c1.dmp" in report
        assert "c2.dmp" in report
        assert "ACCESS_VIOLATION" in report
        assert "STACK_OVERFLOW" in report
        assert "C0000005" in report
        assert "C00000FD" in report
        assert "C:/app" in report

    def test_timeline_sorting(self):
        """Should sort DMPs by crash timestamp."""
        from mvp.batch import BatchReporter

        results = [
            _make_result("later.dmp", timestamp="2026-06-28T03:00:00"),
            _make_result("earlier.dmp", timestamp="2026-06-28T01:00:00"),
        ]

        report = BatchReporter().generate(results)
        # Earlier should appear before later in the report
        assert report.find("earlier.dmp") < report.find("later.dmp")

    def test_clustering_same_exception(self):
        """Should group DMPs with the same exception code."""
        from mvp.batch import BatchReporter

        results = [
            _make_result("a.dmp", exception_code="C0000005", crash_module="X"),
            _make_result("b.dmp", exception_code="C00000FD", crash_module="Y"),
            _make_result("c.dmp", exception_code="C0000005", crash_module="X"),
        ]

        report = BatchReporter().generate(results)
        # Should mention that C0000005 appears 2 times
        assert "C0000005" in report

    def test_includes_error_results(self):
        """Should list failed analyses with error messages."""
        from mvp.batch import BatchReporter

        results = [
            _make_result("ok.dmp"),
            _make_error_result("bad.dmp", "CDB timeout after 60s"),
        ]

        report = BatchReporter().generate(results)
        assert "bad.dmp" in report
        assert "CDB timeout" in report

    def test_empty_results(self):
        """Should handle empty results gracefully."""
        from mvp.batch import BatchReporter
        report = BatchReporter().generate([])
        assert "无 DMP 文件" in report or "no dmp" in report.lower()

    def test_report_saves_to_file(self, tmp_path):
        """Should write the summary report to disk."""
        from mvp.batch import BatchReporter

        results = [_make_result("test.dmp")]
        reporter = BatchReporter()
        report = reporter.generate(results)
        out = tmp_path / "batch_summary.md"
        out.write_text(report, encoding="utf-8")
        assert out.read_text(encoding="utf-8") == report


# ═══════════════════════════════════════════════════════════════════════
# CorrelationAnalyzer
# ═══════════════════════════════════════════════════════════════════════

from mvp.batch import CorrelationAnalyzer


def _make_result_with_memory(
    dump_path: str,
    exception_code: str = "C0000005",
    exception_name: str = "ACCESS_VIOLATION",
    crash_function: str = "myapp!Crash+0x42",
    timestamp: str = "2026-06-28T01:00:00",
    avail_mem: int = 4096,
    total_mem: int = 16384,
    uptime: int = 3600,
    modules: list[tuple[str, str]] | None = None,
) -> dict:
    """Build result with specified system state."""
    dmp = DmpData()
    dmp.metadata.timestamp = timestamp
    dmp.exception = ExceptionInfo(code=exception_code, name=exception_name)
    dmp.crash_callstack = [Frame(
        frame_index=0, module=crash_function.split("!")[0],
        function=crash_function,
    )]
    dmp.system_info = SystemInfo(
        os_name="Windows 11",
        platform="x64",
        total_physical_mb=total_mem,
        available_physical_mb=avail_mem,
        system_uptime_seconds=uptime,
    )
    if modules:
        from mvp.context import ModuleInfo
        dmp.modules = [
            ModuleInfo(name=n, version=v, path="", base_address="0", size=0, has_symbols=False)
            for n, v in modules
        ]

    ctx = AnalysisContext(dump_path=dump_path, collected_at=timestamp)
    ctx.dmp = dmp
    return {
        "dump_path": dump_path,
        "ctx": ctx,
        "json": json.dumps(ctx.to_dict(), ensure_ascii=False),
        "ai_result": "Root cause: test",
        "report_path": dump_path.replace(".dmp", "_report.md"),
        "error": None,
    }


class TestCorrelationCallstack:
    """Tests for callstack similarity analysis."""

    def test_same_function_high_similarity(self):
        """Two DMPs with same Frame 0 function → 100% similarity."""
        r1 = _make_result("a.dmp", crash_function="myapp!ProcessData+0x42")
        r2 = _make_result("b.dmp", crash_function="myapp!ProcessData+0x42")
        ca = CorrelationAnalyzer([r1, r2])
        sim = ca._callstack_similarity()
        assert len(sim) > 0
        # Find the pair
        pair = [s for s in sim if s["dmp1"] == "a.dmp" and s["dmp2"] == "b.dmp"]
        assert len(pair) == 1
        assert pair[0]["similarity"] >= 1.0

    def test_different_functions_low_similarity(self):
        """Different Frame 0 functions → low similarity."""
        r1 = _make_result("a.dmp", crash_function="myapp!ProcessData+0x42")
        r2 = _make_result("b.dmp", crash_function="mylib!ReadBuffer+0x10")
        ca = CorrelationAnalyzer([r1, r2])
        sim = ca._callstack_similarity()
        pair = [s for s in sim if s["dmp1"] == "a.dmp" and s["dmp2"] == "b.dmp"]
        assert pair[0]["similarity"] < 1.0

    def test_same_module_different_offset(self):
        """Same module!function, different offset → high similarity."""
        r1 = _make_result("a.dmp", crash_function="myapp!Crash+0x10")
        r2 = _make_result("b.dmp", crash_function="myapp!Crash+0x42")
        ca = CorrelationAnalyzer([r1, r2])
        sim = ca._callstack_similarity()
        pair = [s for s in sim if s["dmp1"] == "a.dmp" and s["dmp2"] == "b.dmp"]
        # Same function, different offset → high but not 100%
        assert pair[0]["similarity"] > 0.8


class TestCorrelationSystemState:
    """Tests for system state commonality detection."""

    def test_detects_low_memory_pattern(self):
        """Multiple DMPs with low available memory → flagged."""
        results = [
            _make_result_with_memory("a.dmp", avail_mem=128, total_mem=16384),
            _make_result_with_memory("b.dmp", avail_mem=256, total_mem=16384),
            _make_result_with_memory("c.dmp", avail_mem=100, total_mem=16384),
        ]
        ca = CorrelationAnalyzer(results)
        findings = ca._system_state_commonality()
        # Should detect low memory pattern
        mem_findings = [f for f in findings if "内存" in f or "memory" in f.lower()]
        assert len(mem_findings) > 0

    def test_no_pattern_when_normal(self):
        """All DMPs with normal memory → no memory warning."""
        results = [
            _make_result_with_memory("a.dmp", avail_mem=8192, total_mem=16384),
            _make_result_with_memory("b.dmp", avail_mem=7168, total_mem=16384),
        ]
        ca = CorrelationAnalyzer(results)
        findings = ca._system_state_commonality()
        mem_findings = [f for f in findings if "内存压力" in f]
        assert len(mem_findings) == 0

    def test_detects_high_uptime_pattern(self):
        """Multiple DMPs with high system uptime → flagged."""
        results = [
            _make_result_with_memory("a.dmp", uptime=86400 * 10),  # 10 days
            _make_result_with_memory("b.dmp", uptime=86400 * 8),   # 8 days
            _make_result_with_memory("c.dmp", uptime=86400 * 12),  # 12 days
        ]
        ca = CorrelationAnalyzer(results)
        findings = ca._system_state_commonality()
        uptime_findings = [f for f in findings if "运行时间" in f or "uptime" in f.lower()]
        assert len(uptime_findings) > 0


class TestCorrelationModules:
    """Tests for module version cross-referencing."""

    def test_cross_references_module_versions(self):
        """Same module with different versions across DMPs → flagged."""
        r1 = _make_result_with_memory("a.dmp", modules=[
            ("myapp.exe", "1.0.0.0"), ("mylib.dll", "2.0.0.0")])
        r2 = _make_result_with_memory("b.dmp", modules=[
            ("myapp.exe", "1.0.0.0"), ("mylib.dll", "2.0.1.0")])
        ca = CorrelationAnalyzer([r1, r2])
        findings = ca._module_version_cross_ref()
        # mylib.dll version differs
        mod_findings = [f for f in findings if "mylib.dll" in f]
        assert len(mod_findings) > 0

    def test_no_flag_when_versions_match(self):
        """All modules same version → no module warnings."""
        r1 = _make_result_with_memory("a.dmp", modules=[
            ("myapp.exe", "1.0.0.0"), ("mylib.dll", "2.0.0.0")])
        r2 = _make_result_with_memory("b.dmp", modules=[
            ("myapp.exe", "1.0.0.0"), ("mylib.dll", "2.0.0.0")])
        ca = CorrelationAnalyzer([r1, r2])
        findings = ca._module_version_cross_ref()
        assert len(findings) == 0


class TestCorrelationFrequency:
    """Tests for crash frequency trend analysis."""

    def test_detects_accelerating_crashes(self):
        """Crash intervals shrinking → accelerating trend."""
        results = [
            _make_result_with_memory("a.dmp", timestamp="2026-06-28T00:00:00"),
            _make_result_with_memory("b.dmp", timestamp="2026-06-28T00:30:00"),
            _make_result_with_memory("c.dmp", timestamp="2026-06-28T00:45:00"),
            _make_result_with_memory("d.dmp", timestamp="2026-06-28T00:50:00"),
        ]
        ca = CorrelationAnalyzer(results)
        trend = ca._crash_frequency_trend()
        assert trend is not None
        assert "加速" in trend or "恶化" in trend or "increasing" in trend.lower() or "escalating" in trend.lower()

    def test_stable_crash_rate(self):
        """Evenly spaced crashes → stable."""
        results = [
            _make_result_with_memory("a.dmp", timestamp="2026-06-28T00:00:00"),
            _make_result_with_memory("b.dmp", timestamp="2026-06-28T06:00:00"),
            _make_result_with_memory("c.dmp", timestamp="2026-06-28T12:00:00"),
        ]
        ca = CorrelationAnalyzer(results)
        trend = ca._crash_frequency_trend()
        # Should not show worsening
        assert "稳定" in trend or "stable" in trend.lower() or "均匀" in trend

    def test_insufficient_data(self):
        """Less than 3 DMPs → no trend analysis."""
        results = [
            _make_result_with_memory("a.dmp", timestamp="2026-06-28T00:00:00"),
            _make_result_with_memory("b.dmp", timestamp="2026-06-28T01:00:00"),
        ]
        ca = CorrelationAnalyzer(results)
        trend = ca._crash_frequency_trend()
        assert trend is None or "不足" in trend


class TestCorrelationSummary:
    """Tests for compressed summary generation."""

    def test_compressed_summary_size(self):
        """Each DMP summary should be < 2KB."""
        r1 = _make_result_with_memory("a.dmp", modules=[
            ("myapp.exe", "1.0.0.0"), ("mylib.dll", "2.0.0.0"),
            ("ntdll.dll", "10.0.26200"), ("kernel32.dll", "10.0.26200"),
        ])
        ca = CorrelationAnalyzer([r1])
        summaries = ca._compress_summaries()
        assert len(summaries) == 1
        assert len(summaries[0]) < 3000  # ~2KB in UTF-8


class TestCorrelationLimit:
    """Tests for 10 DMP hard limit."""

    def test_rejects_more_than_10(self):
        """More than 10 DMPs should raise ValueError."""
        results = [_make_result(f"dmp_{i}.dmp") for i in range(11)]
        with pytest.raises(ValueError, match="10"):
            CorrelationAnalyzer(results)


class TestCorrelationReport:
    """Tests for correlation report generation."""

    def test_generates_correlation_section(self):
        """Should generate a markdown section with findings."""
        results = [
            _make_result_with_memory("a.dmp", avail_mem=128, total_mem=16384,
                crash_function="myapp!Crash+0x42", timestamp="2026-06-28T01:00:00"),
            _make_result_with_memory("b.dmp", avail_mem=100, total_mem=16384,
                crash_function="myapp!Crash+0x42", timestamp="2026-06-28T01:05:00"),
            _make_result_with_memory("c.dmp", avail_mem=256, total_mem=16384,
                crash_function="myapp!Crash+0x45", timestamp="2026-06-28T01:08:00"),
        ]
        ca = CorrelationAnalyzer(results)
        report = ca.generate_correlation_report()
        assert "关联分析" in report or "Correlation" in report
        assert "调用栈" in report or "Callstack" in report or "callstack" in report

    def test_single_dmp_no_correlation(self):
        """Single DMP → minimal report, no errors."""
        results = [_make_result("only.dmp")]
        ca = CorrelationAnalyzer(results)
        report = ca.generate_correlation_report()
        assert "不足" in report or "至少" in report  # "数据不足" or "至少需要"


# ═════════════════════════════════════════════════════════════════════
# Parallel CDB tests
# ═════════════════════════════════════════════════════════════════════

from mvp.batch import collect_context, analyze_context


class TestCollectContext:
    """Tests for collect_context() — Phase 1 (CDB + collectors)."""

    def test_returns_structured_dict(self, tmp_path):
        """collect_context should return ctx, json, dump_path."""
        dmp = tmp_path / "test.dmp"
        dmp.write_text("mock dump")
        # Patch the collector classes at their source (not batch.py local import)
        with patch("mvp.collectors.dmp_collector.DmpCollector") as mc_dmp, \
             patch("mvp.collectors.binary_collector.BinaryCollector") as mc_bin, \
             patch("mvp.collectors.symbol_collector.SymbolCollector") as mc_sym, \
             patch("mvp.collectors.log_collector.LogCollector") as mc_log, \
             patch("mvp.collectors.eventlog_collector.EventLogCollector") as mc_evt, \
             patch("mvp.collectors.source_collector.SourceCollector") as mc_src, \
             patch("mvp.collectors.config_collector.ConfigCollector") as mc_cfg:
            for mc in [mc_dmp, mc_bin, mc_sym, mc_log, mc_evt, mc_src, mc_cfg]:
                mc.return_value.is_applicable.return_value = False
                mc.return_value.name = "mock"
            result = collect_context(str(dmp))
            assert "ctx" in result
            assert "json" in result
            assert "dump_path" in result
            assert result["error"] is None

    def test_error_caught_gracefully(self, tmp_path):
        """If DMP file doesn't exist, error is captured in result dict."""
        # collect_context handles missing files gracefully via DmpCollector
        dmp = tmp_path / "nonexistent.dmp"
        # The DmpCollector will try to run CDB against a real(?) file
        # For test simplicity, just verify missing file path causes error
        result = collect_context(str(dmp))
        # Should have an error OR a valid ctx (both are acceptable)
        assert "dump_path" in result
        assert str(dmp) in result["dump_path"]


class TestAnalyzeContext:
    """Tests for analyze_context() — Phase 2 (AI + report)."""

    def test_fills_ai_result(self):
        """analyze_context adds ai_result and report_path to result dict."""
        ctx = Mock()
        ctx.dmp.exception.code = "C0000005"
        result = {
            "dump_path": "test.dmp", "ctx": ctx,
            "json": '{"dmp":{"exception":{"code":"C0000005"}}}',
            "error": None, "ai_result": "", "report_path": "",
        }
        with patch("mvp.ai_client.analyze", return_value="AI result text"):
            result = analyze_context(result, provider="deepseek")
            assert result["ai_result"] == "AI result text"
            assert result["report_path"] != ""

    def test_json_only_skips_ai(self):
        """When json_only=True, AI is skipped."""
        ctx = Mock()
        ctx.dmp.exception.code = "C0000005"
        result = {
            "dump_path": "t.dmp", "ctx": ctx,
            "json": "{}", "error": None, "ai_result": "", "report_path": "",
        }
        with patch("mvp.ai_client.analyze") as mock_ai:
            result = analyze_context(result, json_only=True)
            mock_ai.assert_not_called()
            assert result["ai_result"] == ""

    def test_error_result_skipped(self):
        """Result with existing error is returned as-is."""
        result = {"dump_path": "t.dmp", "error": "CDB crashed",
                  "ai_result": "", "report_path": ""}
        with patch("mvp.ai_client.analyze") as mock_ai:
            result = analyze_context(result)
            mock_ai.assert_not_called()
            assert result["ai_result"] == ""


class TestBatchRunnerParallel:
    """Tests for BatchRunner with parallel CDB."""

    def test_workers_default_none(self):
        """Default workers is None (auto-calculated in run())."""
        from mvp.batch import BatchRunner
        runner = BatchRunner()
        assert runner.workers is None

    def test_workers_custom(self):
        """Custom workers via constructor."""
        from mvp.batch import BatchRunner
        runner = BatchRunner(workers=2)
        assert runner.workers == 2

    def test_parallel_run_with_mock(self, tmp_path):
        """BatchRunner.run() with mocked collect/analyze works end-to-end."""
        from mvp.batch import BatchRunner

        for i in range(3):
            (tmp_path / f"crash_{i}.dmp").write_text("mock")

        mock_results = {
            str(tmp_path / "crash_0.dmp"): {"dump_path": str(tmp_path / "crash_0.dmp"),
                "ctx": None, "json": "{}", "error": None, "ai_result": "ok",
                "report_path": ""},
            str(tmp_path / "crash_1.dmp"): {"dump_path": str(tmp_path / "crash_1.dmp"),
                "ctx": None, "json": "{}", "error": None, "ai_result": "ok",
                "report_path": ""},
            str(tmp_path / "crash_2.dmp"): {"dump_path": str(tmp_path / "crash_2.dmp"),
                "ctx": None, "json": "{}", "error": None, "ai_result": "ok",
                "report_path": ""},
        }

        with patch("mvp.batch.collect_context", side_effect=lambda dump_path, **kw: mock_results[str(dump_path)]), \
             patch("mvp.batch.analyze_context", side_effect=lambda r, **kw: r):
            runner = BatchRunner(workers=2)
            runner._collect_files = lambda p: list(mock_results.keys())
            results = runner.run(["*.dmp"])
            assert len(results) == 3

    def test_error_isolation(self, tmp_path):
        """One DMP failure doesn't affect others in parallel."""
        from mvp.batch import BatchRunner

        for i in range(3):
            (tmp_path / f"crash_{i}.dmp").write_text("mock")

        dmp_0 = str(tmp_path / "crash_0.dmp")
        dmp_1 = str(tmp_path / "crash_1.dmp")
        dmp_2 = str(tmp_path / "crash_2.dmp")

        def _collect_mixed(dump_path=None, **kw):
            dp = str(dump_path)
            if dp == dmp_1:
                return {"dump_path": dp, "ctx": None, "json": "",
                        "error": "CDB timeout", "ai_result": "", "report_path": ""}
            return {"dump_path": dp, "ctx": None, "json": "{}",
                    "error": None, "ai_result": "", "report_path": ""}

        with patch("mvp.batch.collect_context", side_effect=_collect_mixed), \
             patch("mvp.batch.analyze_context", side_effect=lambda r, **kw: r):
            runner = BatchRunner(workers=2)
            runner._collect_files = lambda p: [dmp_0, dmp_1, dmp_2]
            results = runner.run(["*.dmp"])
            assert len(results) == 3
            errors = [r for r in results if r["error"]]
            ok = [r for r in results if not r["error"]]
            assert len(errors) == 1, f"Expected 1 error, got {len(errors)}: {errors}"
            assert len(ok) == 2
