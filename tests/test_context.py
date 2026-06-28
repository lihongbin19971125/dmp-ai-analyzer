"""Tests for context.py data models.

Covers all dataclass to_dict() serialization, default values, nested
recursive serialization, and JSON-serializability of the full context.
"""

import json

import pytest

from mvp.context import (
    AnalysisContext,
    BinaryInfo,
    ConfigInfo,
    DmpData,
    DmpMetadata,
    ExceptionInfo,
    Frame,
    HeapInfo,
    LockInfo,
    LogInfo,
    ModuleInfo,
    SourceCodeSnippet,
    SourceInfo,
    SymbolInfo,
    SystemEventInfo,
    SystemInfo,
    ThreadStack,
)


# ---------------------------------------------------------------------------
# SystemInfo
# ---------------------------------------------------------------------------

class TestSystemInfo:
    """Tests for SystemInfo dataclass — crash machine data from DMP."""

    def test_system_info_defaults(self):
        """Verify SystemInfo dataclass default values.

        All string fields should default to '' (or None for Optional[str]),
        int fields to 0, list fields to [], and dict fields to {}.
        """
        si = SystemInfo()

        # String fields (default "")
        assert si.os_name == ""
        assert si.os_version == ""
        assert si.os_build == ""
        assert si.platform == ""

        # Int fields (default 0)
        assert si.cpu_count == 0
        assert si.total_physical_mb == 0
        assert si.available_physical_mb == 0
        assert si.total_virtual_mb == 0
        assert si.total_pagefile_mb == 0
        assert si.process_working_set_mb == 0
        assert si.process_pagefile_mb == 0
        assert si.system_uptime_seconds == 0

        # String field (default "")
        assert si.cpu_model == ""

        # List field (default empty list)
        assert si.cpu_features == []
        assert isinstance(si.cpu_features, list)

        # Dict field (default empty dict)
        assert si.environment == {}
        assert isinstance(si.environment, dict)

        # Optional[str] fields (default None)
        assert si.boot_time is None
        assert si.machine_name is None
        assert si.memory_pressure_reason is None

    def test_system_info_to_dict_full(self):
        """Verify to_dict() serializes all 18 fields correctly including nested dicts.

        The output dict must contain every key that to_dict() explicitly writes,
        with correct types: strings, ints, lists, dicts, and None values preserved.
        """
        si = SystemInfo(
            os_name="Windows 10",
            os_version="10.0.22621",
            os_build="22621",
            platform="x64",
            cpu_count=8,
            cpu_model="Intel Core i7",
            cpu_features=["AVX", "SSE2"],
            total_physical_mb=16384,
            available_physical_mb=8192,
            total_pagefile_mb=24576,
            process_working_set_mb=512,
            system_uptime_seconds=100000,
            boot_time="2026-06-23",
            machine_name="PC01",
            environment={"KEY": "VAL"},
        )

        d = si.to_dict()

        # Verify all 18 keys are present
        expected_keys = {
            "os_name", "os_version", "os_build", "platform",
            "cpu_count", "cpu_model", "cpu_features",
            "total_physical_mb", "available_physical_mb",
            "total_virtual_mb", "total_pagefile_mb",
            "process_working_set_mb", "process_pagefile_mb",
            "system_uptime_seconds", "boot_time", "machine_name",
            "environment", "memory_pressure_reason",
        }
        assert set(d.keys()) == expected_keys

        # String fields
        assert d["os_name"] == "Windows 10"
        assert d["os_version"] == "10.0.22621"
        assert d["os_build"] == "22621"
        assert d["platform"] == "x64"
        assert d["cpu_model"] == "Intel Core i7"
        assert d["boot_time"] == "2026-06-23"
        assert d["machine_name"] == "PC01"

        # Int fields
        assert d["cpu_count"] == 8
        assert d["total_physical_mb"] == 16384
        assert d["available_physical_mb"] == 8192
        assert d["total_pagefile_mb"] == 24576
        assert d["process_working_set_mb"] == 512
        assert d["system_uptime_seconds"] == 100000

        # Default int fields (not explicitly set)
        assert d["total_virtual_mb"] == 0
        assert d["process_pagefile_mb"] == 0

        # List field
        assert d["cpu_features"] == ["AVX", "SSE2"]
        assert isinstance(d["cpu_features"], list)

        # Dict field
        assert d["environment"] == {"KEY": "VAL"}
        assert isinstance(d["environment"], dict)

        # None field (not set, should be None)
        assert d["memory_pressure_reason"] is None


# ---------------------------------------------------------------------------
# Frame
# ---------------------------------------------------------------------------

class TestFrame:
    """Tests for Frame dataclass — single stack frame."""

    def test_frame_to_dict(self):
        """Verify Frame.to_dict() serialization.

        All fields including Optional[str] source_file and Optional[int]
        source_line should appear in the output dict.
        """
        frame = Frame(
            frame_index=3,
            module="mylib",
            function="mylib!DoWork+0x42",
            offset="+0x1240",
            source_file="src/work.cpp",
            source_line=156,
        )

        d = frame.to_dict()

        assert d == {
            "frame_index": 3,
            "module": "mylib",
            "function": "mylib!DoWork+0x42",
            "offset": "+0x1240",
            "source_file": "src/work.cpp",
            "source_line": 156,
        }

    def test_frame_to_dict_defaults(self):
        """Verify Frame.to_dict() with default values.

        Optional fields should serialize as None, string fields as ''.
        """
        frame = Frame()

        d = frame.to_dict()

        assert d["frame_index"] == 0
        assert d["module"] == ""
        assert d["function"] == ""
        assert d["offset"] == ""
        assert d["source_file"] is None
        assert d["source_line"] is None


# ---------------------------------------------------------------------------
# ThreadStack
# ---------------------------------------------------------------------------

class TestThreadStack:
    """Tests for ThreadStack dataclass — thread with nested callstack frames."""

    def test_thread_stack_to_dict(self):
        """Verify ThreadStack serializes nested frames recursively.

        Each Frame in callstack should be converted via its own to_dict(),
        producing a list of nested dicts.
        """
        ts = ThreadStack(
            thread_id=0x1A90,
            state="crashed",
            callstack=[
                Frame(
                    frame_index=0,
                    module="myapp",
                    function="myapp!CrashFunc+0x10",
                    offset="",
                    source_file=None,
                    source_line=None,
                ),
                Frame(
                    frame_index=1,
                    module="myapp",
                    function="myapp!main+0x42",
                    offset="",
                    source_file=None,
                    source_line=None,
                ),
            ],
        )

        d = ts.to_dict()

        # thread_id 0x1A90 == 6800
        assert d["thread_id"] == 6800
        assert d["state"] == "crashed"
        assert len(d["callstack"]) == 2

        # First frame
        f0 = d["callstack"][0]
        assert f0["frame_index"] == 0
        assert f0["module"] == "myapp"
        assert f0["function"] == "myapp!CrashFunc+0x10"
        assert f0["offset"] == ""
        assert f0["source_file"] is None
        assert f0["source_line"] is None

        # Second frame
        f1 = d["callstack"][1]
        assert f1["frame_index"] == 1
        assert f1["module"] == "myapp"
        assert f1["function"] == "myapp!main+0x42"

    def test_thread_stack_empty_callstack(self):
        """Verify ThreadStack.to_dict() with an empty callstack."""
        ts = ThreadStack(thread_id=42, state="running")
        d = ts.to_dict()

        assert d["thread_id"] == 42
        assert d["state"] == "running"
        assert d["callstack"] == []
        assert isinstance(d["callstack"], list)


# ---------------------------------------------------------------------------
# ExceptionInfo
# ---------------------------------------------------------------------------

class TestExceptionInfo:
    """Tests for ExceptionInfo dataclass — exception details from DMP."""

    def test_exception_info_defaults(self):
        """Verify ExceptionInfo default values.

        first_chance should default to True, in_page_error to False,
        security_violation to False. All string fields default to ''.
        """
        ei = ExceptionInfo()

        # String fields
        assert ei.code == ""
        assert ei.name == ""
        assert ei.address == ""
        assert ei.type == ""
        assert ei.attempted_address == ""

        # Bool fields with non-False defaults
        assert ei.first_chance is True
        assert ei.in_page_error is False
        assert ei.security_violation is False


# ---------------------------------------------------------------------------
# ModuleInfo
# ---------------------------------------------------------------------------

class TestModuleInfo:
    """Tests for ModuleInfo dataclass — loaded module at crash time."""

    def test_module_info_no_symbols(self):
        """Verify ModuleInfo defaults and to_dict for a module without symbols.

        has_symbols should default to False. Optional fields version and
        timestamp should serialize as None when not provided.
        """
        mi = ModuleInfo(
            name="unknown.dll",
            base_address="0000012340000000",
            size=1048576,
            has_symbols=False,
        )

        d = mi.to_dict()

        assert d["name"] == "unknown.dll"
        assert d["path"] == ""
        assert d["base_address"] == "0000012340000000"
        assert d["size"] == 1048576
        assert d["has_symbols"] is False
        assert d["version"] is None
        assert d["timestamp"] is None

    def test_module_info_with_symbols(self):
        """Verify ModuleInfo.to_dict() when symbols are available."""
        mi = ModuleInfo(
            name="myapp.exe",
            path="C:\\Program Files\\MyApp\\myapp.exe",
            base_address="00007FF700000000",
            size=524288,
            version="1.2.3.4",
            timestamp="2026-06-01T12:00:00Z",
            has_symbols=True,
        )

        d = mi.to_dict()

        assert d["name"] == "myapp.exe"
        assert d["path"] == "C:\\Program Files\\MyApp\\myapp.exe"
        assert d["base_address"] == "00007FF700000000"
        assert d["size"] == 524288
        assert d["version"] == "1.2.3.4"
        assert d["timestamp"] == "2026-06-01T12:00:00Z"
        assert d["has_symbols"] is True


# ---------------------------------------------------------------------------
# DmpData
# ---------------------------------------------------------------------------

class TestDmpData:
    """Tests for DmpData — the core dump analysis result aggregator."""

    def test_dmp_data_to_dict_full(self):
        """Verify DmpData.to_dict() produces correct structure with nested serialization.

        The output dict must contain all expected top-level keys, and each
        nested value must be the to_dict() output of its respective dataclass.
        """
        dmp = DmpData()
        dmp.exception = ExceptionInfo(code="C0000005", name="ACCESS_VIOLATION")
        dmp.system_info = SystemInfo(os_name="Windows 10", platform="x64")
        dmp.heap = HeapInfo(heap_count=3, corrupted=False)

        result = dmp.to_dict()

        # Top-level keys
        expected_keys = {
            "system_info", "metadata", "exception", "crash_callstack",
            "all_callstacks", "registers", "modules", "locks", "heap",
            "address_summary", "memory_findings", "raw_analyze_output",
        }
        assert set(result.keys()) == expected_keys

        # Nested dicts should reflect their dataclass to_dict() output
        assert result["system_info"]["os_name"] == "Windows 10"
        assert result["system_info"]["platform"] == "x64"
        assert result["exception"]["code"] == "C0000005"
        assert result["exception"]["name"] == "ACCESS_VIOLATION"
        assert result["heap"]["heap_count"] == 3
        assert result["heap"]["corrupted"] is False

        # Collections should be empty lists/dicts by default
        assert result["crash_callstack"] == []
        assert result["all_callstacks"] == []
        assert result["registers"] == {}
        assert result["modules"] == []
        assert result["locks"] == []

        # Default string
        assert result["raw_analyze_output"] == ""

    def test_dmp_data_to_dict_serializable(self):
        """DmpData.to_dict() output should be JSON-serializable."""
        dmp = DmpData()
        dmp.system_info = SystemInfo(os_name="Windows 10", platform="x64")
        dmp.metadata = DmpMetadata(
            dump_type="minidump",
            timestamp="2026-06-27T10:30:00Z",
            process_name="myapp.exe",
            process_id=12345,
        )
        dmp.exception = ExceptionInfo(code="C0000005", name="ACCESS_VIOLATION")
        dmp.crash_callstack = [
            Frame(frame_index=0, module="mylib.dll",
                  function="mylib!ProcessData+0x42")
        ]
        dmp.registers = {"rax": "0000000000000000", "rip": "00007FF812340000"}
        dmp.raw_analyze_output = "CDB output text..."

        result = dmp.to_dict()
        json_str = json.dumps(result)
        assert len(json_str) > 0
        assert "C0000005" in json_str
        assert "mylib!ProcessData" in json_str


# ---------------------------------------------------------------------------
# SourceCodeSnippet
# ---------------------------------------------------------------------------

class TestSourceCodeSnippet:
    """Tests for SourceCodeSnippet dataclass."""

    def test_source_code_snippet_to_dict(self):
        """Verify SourceCodeSnippet serialization.

        All fields (file_path, crash_line, start_line, end_line, code)
        should appear in the output dict with correct values.
        """
        snippet = SourceCodeSnippet(
            file_path="/src/main.cpp",
            crash_line=42,
            start_line=12,
            end_line=72,
            code="  >>>     42 | foo->bar()",
        )

        d = snippet.to_dict()

        assert d == {
            "file_path": "/src/main.cpp",
            "crash_line": 42,
            "start_line": 12,
            "end_line": 72,
            "code": "  >>>     42 | foo->bar()",
        }

    def test_source_code_snippet_defaults(self):
        """Verify SourceCodeSnippet default values serialize correctly."""
        snippet = SourceCodeSnippet()

        d = snippet.to_dict()

        assert d["file_path"] == ""
        assert d["crash_line"] == 0
        assert d["start_line"] == 0
        assert d["end_line"] == 0
        assert d["code"] == ""


# ---------------------------------------------------------------------------
# AnalysisContext
# ---------------------------------------------------------------------------

class TestAnalysisContext:
    """Tests for AnalysisContext — top-level context aggregating all collectors."""

    def test_analysis_context_to_dict_complete(self):
        """Verify AnalysisContext.to_dict() serializes all optional context layers when present.

        When all optional collectors (binaries, symbols, logs, system_events,
        source, config) are set, all their keys must appear in the output dict.
        source and system_events omitted when set (source is set, so included).
        Meta and dmp keys are always present.
        """
        ctx = AnalysisContext(
            dump_path="test.dmp",
            exe_dir="/app",
            source_dir="/src",
            log_dir="/logs",
            collected_at="2026-06-23T15:26:44",
        )
        ctx.binaries = BinaryInfo(
            modules_found=[{"name": "myapp.exe"}],
            modules_missing=["missing.dll"],
        )
        ctx.symbols = SymbolInfo(
            module_symbols={"myapp.exe": "found: myapp.pdb"},
        )
        ctx.logs = LogInfo(
            files_found=["app.log"],
            error_summary=["ERROR: something"],
        )
        ctx.config = ConfigInfo(
            config_files=["config.json"],
            key_settings={"config.json": "{...}"},
        )

        result = ctx.to_dict()

        # Mandatory keys
        assert "meta" in result
        assert "dmp" in result

        # Optional keys present (all set)
        assert "binaries" in result
        assert "symbols" in result
        assert "logs" in result
        assert "config" in result

        # Not set: system_events, source
        assert "system_events" not in result
        assert "source" not in result

        # Meta contents
        assert result["meta"]["dump_path"] == "test.dmp"
        assert result["meta"]["exe_dir"] == "/app"
        assert result["meta"]["source_dir"] == "/src"
        assert result["meta"]["log_dir"] == "/logs"
        assert result["meta"]["collected_at"] == "2026-06-23T15:26:44"

        # Binaries contents
        assert result["binaries"]["modules_found"] == [{"name": "myapp.exe"}]
        assert isinstance(result["binaries"]["modules_found"], list)
        assert result["binaries"]["modules_missing"] == ["missing.dll"]

        # Symbols contents
        assert result["symbols"]["module_symbols"] == {"myapp.exe": "found: myapp.pdb"}
        assert isinstance(result["symbols"]["module_symbols"], dict)

        # Logs contents
        assert result["logs"]["files_found"] == ["app.log"]
        assert result["logs"]["error_summary"] == ["ERROR: something"]

        # Config contents
        assert result["config"]["config_files"] == ["config.json"]
        assert result["config"]["key_settings"] == {"config.json": "{...}"}

    def test_analysis_context_to_dict_sparse(self):
        """Verify AnalysisContext.to_dict() when no optional collectors ran.

        When all optional fields are None, the output dict should only
        contain the mandatory keys: meta and dmp.
        """
        ctx = AnalysisContext(
            dump_path="test.dmp",
            collected_at="2026-06-23",
        )

        result = ctx.to_dict()

        assert set(result.keys()) == {"meta", "dmp"}

        # Verify none of the optional keys leaked in
        for optional_key in ("binaries", "symbols", "logs",
                             "system_events", "source", "config"):
            assert optional_key not in result, f"'{optional_key}' should not be present"

        # Verify meta contents are correct
        assert result["meta"]["dump_path"] == "test.dmp"
        assert result["meta"]["collected_at"] == "2026-06-23"
        assert result["meta"]["exe_dir"] is None
        assert result["meta"]["source_dir"] is None
        assert result["meta"]["log_dir"] is None

    def test_json_serializable(self):
        """Prove that to_dict() output is JSON-serializable via json.dumps.

        json.dumps() must not raise TypeError. The resulting JSON string
        must contain the top-level 'meta' and 'dmp' keys.
        """
        ctx = AnalysisContext(
            dump_path="/tmp/crash.dmp",
            collected_at="2026-01-01T00:00:00",
        )

        json_str = json.dumps(ctx.to_dict(), ensure_ascii=False)

        assert isinstance(json_str, str)
        assert len(json_str) > 0

        # Verify it round-trips
        parsed = json.loads(json_str)
        assert "meta" in parsed
        assert "dmp" in parsed
        assert parsed["meta"]["dump_path"] == "/tmp/crash.dmp"
        assert parsed["meta"]["collected_at"] == "2026-01-01T00:00:00"

    def test_empty_context(self):
        """Empty AnalysisContext should produce valid JSON."""
        ctx = AnalysisContext()
        ctx.collected_at = "2026-01-01T00:00:00"
        d = ctx.to_dict()
        assert d["meta"]["collected_at"] == "2026-01-01T00:00:00"
        assert "dmp" in d
        json.dumps(d)  # shouldn't raise

    def test_with_optional_collectors(self):
        """Context with optional collectors should include their data."""
        ctx = AnalysisContext()
        ctx.binaries = BinaryInfo(
            modules_found=[{"dmp_name": "mylib.dll", "version": "1.2.3"}],
            modules_missing=["unknown.dll"],
        )
        ctx.source = SourceInfo(
            snippets=[SourceCodeSnippet(
                file_path="process.cpp",
                crash_line=342,
                start_line=312,
                end_line=372,
                code=">>>    342 | buffer = nullptr;",
            )],
            recent_git_changes=["abc1234 Fix: buffer handling"],
            working_tree_dirty=True,
        )
        d = ctx.to_dict()
        assert "binaries" in d
        assert d["binaries"]["modules_missing"] == ["unknown.dll"]
        assert "source" in d
        assert len(d["source"]["snippets"]) == 1
        assert d["source"]["working_tree_dirty"] is True

    def test_attribute_names(self):
        """Internal flag attributes should be settable."""
        ctx = AnalysisContext()
        # _collect_system_logs is set dynamically by CLI
        ctx._collect_system_logs = True  # type: ignore
        assert ctx._collect_system_logs is True  # type: ignore


# ---------------------------------------------------------------------------
# LockInfo
# ---------------------------------------------------------------------------

class TestLockInfo:
    """Tests for LockInfo dataclass."""

    def test_to_dict(self):
        """Verify LockInfo.to_dict() serialization."""
        lock = LockInfo(
            lock_type="critical_section",
            address="00007FF812340000",
            owner_thread=42,
            waiter_count=3,
        )

        d = lock.to_dict()

        assert d == {
            "lock_type": "critical_section",
            "address": "00007FF812340000",
            "owner_thread": 42,
            "waiter_count": 3,
        }

    def test_defaults(self):
        """Verify LockInfo default values."""
        lock = LockInfo()
        d = lock.to_dict()
        assert d["lock_type"] == ""
        assert d["address"] == ""
        assert d["owner_thread"] == 0
        assert d["waiter_count"] == 0


# ---------------------------------------------------------------------------
# HeapInfo
# ---------------------------------------------------------------------------

class TestHeapInfo:
    """Tests for HeapInfo dataclass."""

    def test_to_dict(self):
        """Verify HeapInfo.to_dict() serialization."""
        heap = HeapInfo(
            total_committed_mb=128,
            total_reserved_mb=256,
            heap_count=3,
            corrupted=False,
            details=["heap0: ok", "heap1: ok"],
        )

        d = heap.to_dict()

        assert d["total_committed_mb"] == 128
        assert d["total_reserved_mb"] == 256
        assert d["heap_count"] == 3
        assert d["corrupted"] is False
        assert d["details"] == ["heap0: ok", "heap1: ok"]

    def test_defaults(self):
        """Verify HeapInfo default values."""
        heap = HeapInfo()
        d = heap.to_dict()
        assert d["total_committed_mb"] == 0
        assert d["total_reserved_mb"] == 0
        assert d["heap_count"] == 0
        assert d["corrupted"] is False
        assert d["details"] == []

    def test_new_fields(self):
        """HeapInfo with free_bytes, segment_count, lfh_enabled, per_heap."""
        heap = HeapInfo(
            total_committed_mb=512,
            total_reserved_mb=1024,
            free_bytes=64_000_000,
            segment_count=8,
            lfh_enabled=True,
            heap_count=3,
            per_heap_breakdown=[
                {"address": "0x1000", "commit_mb": 200, "reserve_mb": 400, "segments": 2},
                {"address": "0x2000", "commit_mb": 312, "reserve_mb": 624, "segments": 6},
            ],
        )
        d = heap.to_dict()
        assert d["free_bytes"] == 64_000_000
        assert d["segment_count"] == 8
        assert d["lfh_enabled"] is True
        assert len(d["per_heap_breakdown"]) == 2
        assert d["per_heap_breakdown"][0]["address"] == "0x1000"

    def test_per_heap_breakdown_default(self):
        """Per-heap breakdown is empty list by default."""
        heap = HeapInfo()
        assert heap.per_heap_breakdown == []
        assert heap.to_dict()["per_heap_breakdown"] == []

    def test_heap_json_serializable(self):
        """HeapInfo with per-heap dicts is JSON-serializable."""
        import json as _json
        heap = HeapInfo(
            total_committed_mb=100,
            per_heap_breakdown=[
                {"address": "0x1000", "commit_mb": 100, "reserve_mb": 200, "segments": 1},
            ],
        )
        s = _json.dumps(heap.to_dict())
        assert "per_heap_breakdown" in s
        assert "0x1000" in s


# ---------------------------------------------------------------------------
# DmpData new fields
# ---------------------------------------------------------------------------

class TestDmpDataNewFields:
    """Tests for address_summary and memory_findings on DmpData."""

    def test_address_summary_default(self):
        """DmpData has empty address_summary dict by default."""
        dmp = DmpData()
        assert dmp.address_summary == {}
        d = dmp.to_dict()
        assert "address_summary" in d

    def test_memory_findings_default(self):
        """DmpData has empty memory_findings list by default."""
        dmp = DmpData()
        assert dmp.memory_findings == []

    def test_to_dict_includes_new_fields(self):
        """DmpData.to_dict() includes address_summary and memory_findings."""
        dmp = DmpData()
        dmp.address_summary = {"Free": "2048 MB", "Image": "256 MB"}
        dmp.memory_findings = [
            {"indicator": "high_commit", "severity": "high",
             "evidence": "512MB committed", "recommendation": "Check for leaks"}
        ]
        d = dmp.to_dict()
        assert d["address_summary"] == dmp.address_summary
        assert len(d["memory_findings"]) == 1
        assert d["memory_findings"][0]["severity"] == "high"

class TestBinaryInfo:
    """Tests for BinaryInfo dataclass."""

    def test_to_dict(self):
        """Verify BinaryInfo.to_dict() serialization."""
        bi = BinaryInfo(
            modules_found=[{"dmp_name": "mylib.dll", "version": "1.2.3"}],
            modules_missing=["unknown.dll"],
            main_exe_version="2.0.0",
            recently_modified_files=["config.ini"],
        )

        d = bi.to_dict()

        assert d["modules_found"] == [{"dmp_name": "mylib.dll", "version": "1.2.3"}]
        assert d["modules_missing"] == ["unknown.dll"]
        assert d["main_exe_version"] == "2.0.0"
        assert d["recently_modified_files"] == ["config.ini"]


# ---------------------------------------------------------------------------
# SymbolInfo
# ---------------------------------------------------------------------------

class TestSymbolInfo:
    """Tests for SymbolInfo dataclass."""

    def test_to_dict(self):
        """Verify SymbolInfo.to_dict() serialization."""
        si = SymbolInfo(
            module_symbols={"myapp.exe": "found: myapp.pdb"},
            source_file_map={"myapp.exe": "/src/myapp"},
            mismatches=["PdbSigCheck: mylib.dll vs mylib.pdb"],
        )

        d = si.to_dict()

        assert d["module_symbols"] == {"myapp.exe": "found: myapp.pdb"}
        assert d["source_file_map"] == {"myapp.exe": "/src/myapp"}
        assert d["mismatches"] == ["PdbSigCheck: mylib.dll vs mylib.pdb"]


# ---------------------------------------------------------------------------
# SystemEventInfo
# ---------------------------------------------------------------------------

class TestSystemEventInfo:
    """Tests for SystemEventInfo dataclass."""

    def test_to_dict(self):
        """Verify SystemEventInfo.to_dict() serialization."""
        sei = SystemEventInfo(
            application_events=[{"id": 1000, "message": "App crash"}],
            system_events=[{"id": 41, "message": "Kernel power"}],
        )

        d = sei.to_dict()

        assert d["application_events"] == [{"id": 1000, "message": "App crash"}]
        assert d["system_events"] == [{"id": 41, "message": "Kernel power"}]
