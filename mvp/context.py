"""Unified analysis context data model.

All collectors fill in parts of this context. The assembled context
is serialized to JSON and sent to the AI for analysis.
"""

from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# DMP core data
# ---------------------------------------------------------------------------

@dataclass
class SystemInfo:
    """★ Crash machine system info — ALL extracted from the DMP file itself,
    NEVER from the analysis machine. A developer's 64 GB workstation tells
    you nothing about a customer's 8 GB thin client that ran out of memory.
    """
    os_name: str = ""
    os_version: str = ""
    os_build: str = ""
    platform: str = ""                # x86 / x64 / ARM64
    cpu_count: int = 0
    cpu_model: str = ""
    cpu_features: list[str] = field(default_factory=list)
    total_physical_mb: int = 0
    available_physical_mb: int = 0
    total_virtual_mb: int = 0
    total_pagefile_mb: int = 0
    process_working_set_mb: int = 0
    process_pagefile_mb: int = 0
    system_uptime_seconds: int = 0
    boot_time: Optional[str] = None
    machine_name: Optional[str] = None
    environment: dict[str, str] = field(default_factory=dict)
    memory_pressure_reason: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "os_name": self.os_name,
            "os_version": self.os_version,
            "os_build": self.os_build,
            "platform": self.platform,
            "cpu_count": self.cpu_count,
            "cpu_model": self.cpu_model,
            "cpu_features": self.cpu_features,
            "total_physical_mb": self.total_physical_mb,
            "available_physical_mb": self.available_physical_mb,
            "total_virtual_mb": self.total_virtual_mb,
            "total_pagefile_mb": self.total_pagefile_mb,
            "process_working_set_mb": self.process_working_set_mb,
            "process_pagefile_mb": self.process_pagefile_mb,
            "system_uptime_seconds": self.system_uptime_seconds,
            "boot_time": self.boot_time,
            "machine_name": self.machine_name,
            "environment": self.environment,
            "memory_pressure_reason": self.memory_pressure_reason,
        }


@dataclass
class DmpMetadata:
    dump_type: str = ""               # minidump / full / kernel
    timestamp: str = ""               # ISO format crash time
    os_version: str = ""
    process_name: str = ""
    process_id: int = 0


@dataclass
class ExceptionInfo:
    code: str = ""                    # e.g. "C0000005"
    name: str = ""                    # e.g. "ACCESS_VIOLATION"
    address: str = ""                 # faulting instruction address
    type: str = ""                    # read / write / execute / unknown
    attempted_address: str = ""       # address that was accessed
    first_chance: bool = True
    in_page_error: bool = False
    security_violation: bool = False


@dataclass
class Frame:
    frame_index: int = 0
    module: str = ""                  # mylib.dll
    function: str = ""                # mylib!ProcessData+0x42
    offset: str = ""                  # +0x1240
    source_file: Optional[str] = None # d:\src\process.cpp
    source_line: Optional[int] = None # 342

    def to_dict(self) -> dict:
        return {
            "frame_index": self.frame_index,
            "module": self.module,
            "function": self.function,
            "offset": self.offset,
            "source_file": self.source_file,
            "source_line": self.source_line,
        }


@dataclass
class ThreadStack:
    thread_id: int = 0
    state: str = ""                   # crashed / running / waiting / suspended
    callstack: list[Frame] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "thread_id": self.thread_id,
            "state": self.state,
            "callstack": [f.to_dict() for f in self.callstack],
        }


@dataclass
class ModuleInfo:
    name: str = ""                    # mylib.dll
    path: str = ""                    # disk path at crash time
    base_address: str = ""            # load address
    size: int = 0
    version: Optional[str] = None
    timestamp: Optional[str] = None
    has_symbols: bool = False

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "base_address": self.base_address,
            "size": self.size,
            "version": self.version,
            "timestamp": self.timestamp,
            "has_symbols": self.has_symbols,
        }


@dataclass
class LockInfo:
    lock_type: str = ""               # critical_section / mutex / srwlock
    address: str = ""
    owner_thread: int = 0
    waiter_count: int = 0

    def to_dict(self) -> dict:
        return {
            "lock_type": self.lock_type,
            "address": self.address,
            "owner_thread": self.owner_thread,
            "waiter_count": self.waiter_count,
        }


@dataclass
class HeapInfo:
    total_committed_mb: int = 0
    total_reserved_mb: int = 0
    free_bytes: int = 0
    segment_count: int = 0
    heap_count: int = 0
    lfh_enabled: bool = False
    corrupted: bool = False
    details: list[str] = field(default_factory=list)
    per_heap_breakdown: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "total_committed_mb": self.total_committed_mb,
            "total_reserved_mb": self.total_reserved_mb,
            "free_bytes": self.free_bytes,
            "segment_count": self.segment_count,
            "heap_count": self.heap_count,
            "lfh_enabled": self.lfh_enabled,
            "corrupted": self.corrupted,
            "details": self.details,
            "per_heap_breakdown": self.per_heap_breakdown,
        }


@dataclass
class DmpData:
    system_info: SystemInfo = field(default_factory=SystemInfo)
    metadata: DmpMetadata = field(default_factory=DmpMetadata)
    exception: ExceptionInfo = field(default_factory=ExceptionInfo)
    crash_callstack: list[Frame] = field(default_factory=list)
    all_callstacks: list[ThreadStack] = field(default_factory=list)
    registers: dict[str, str] = field(default_factory=dict)
    modules: list[ModuleInfo] = field(default_factory=list)
    locks: list[LockInfo] = field(default_factory=list)
    heap: HeapInfo = field(default_factory=HeapInfo)
    address_summary: dict = field(default_factory=dict)
    memory_findings: list[dict] = field(default_factory=list)
    raw_analyze_output: str = ""

    def to_dict(self) -> dict:
        return {
            "system_info": self.system_info.to_dict(),
            "metadata": {
                "dump_type": self.metadata.dump_type,
                "timestamp": self.metadata.timestamp,
                "os_version": self.metadata.os_version,
                "process_name": self.metadata.process_name,
                "process_id": self.metadata.process_id,
            },
            "exception": {
                "code": self.exception.code,
                "name": self.exception.name,
                "address": self.exception.address,
                "type": self.exception.type,
                "attempted_address": self.exception.attempted_address,
                "first_chance": self.exception.first_chance,
                "in_page_error": self.exception.in_page_error,
                "security_violation": self.exception.security_violation,
            },
            "crash_callstack": [f.to_dict() for f in self.crash_callstack],
            "all_callstacks": [t.to_dict() for t in self.all_callstacks],
            "registers": self.registers,
            "modules": [m.to_dict() for m in self.modules],
            "locks": [l.to_dict() for l in self.locks],
            "heap": self.heap.to_dict(),
            "address_summary": self.address_summary,
            "memory_findings": self.memory_findings,
            "raw_analyze_output": self.raw_analyze_output,
        }


# ---------------------------------------------------------------------------
# Context layers (filled by optional collectors)
# ---------------------------------------------------------------------------

@dataclass
class BinaryInfo:
    """Information about binary files on disk, matched from DMP module list."""
    modules_found: list[dict] = field(default_factory=list)
    modules_missing: list[str] = field(default_factory=list)
    main_exe_version: Optional[str] = None
    recently_modified_files: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "modules_found": self.modules_found,
            "modules_missing": self.modules_missing,
            "main_exe_version": self.main_exe_version,
            "recently_modified_files": self.recently_modified_files,
        }


@dataclass
class SymbolInfo:
    """Symbol resolution status for each module."""
    module_symbols: dict[str, str] = field(default_factory=dict)  # module -> status
    source_file_map: dict[str, str] = field(default_factory=dict)  # module -> source_root
    mismatches: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "module_symbols": self.module_symbols,
            "source_file_map": self.source_file_map,
            "mismatches": self.mismatches,
        }


@dataclass
class LogInfo:
    """Application log excerpts around crash time."""
    files_found: list[str] = field(default_factory=list)
    crash_window_logs: str = ""       # log lines near crash time
    error_summary: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "files_found": self.files_found,
            "crash_window_logs": self.crash_window_logs,
            "error_summary": self.error_summary,
        }


@dataclass
class SystemEventInfo:
    """Windows event log entries around crash time."""
    application_events: list[dict] = field(default_factory=list)
    system_events: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "application_events": self.application_events,
            "system_events": self.system_events,
        }


@dataclass
class SourceCodeSnippet:
    file_path: str = ""
    crash_line: int = 0
    start_line: int = 0
    end_line: int = 0
    code: str = ""

    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path,
            "crash_line": self.crash_line,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "code": self.code,
        }


@dataclass
class SourceInfo:
    """Source code context around crash locations."""
    snippets: list[SourceCodeSnippet] = field(default_factory=list)
    recent_git_changes: list[str] = field(default_factory=list)
    working_tree_dirty: bool = False

    def to_dict(self) -> dict:
        return {
            "snippets": [s.to_dict() for s in self.snippets],
            "recent_git_changes": self.recent_git_changes,
            "working_tree_dirty": self.working_tree_dirty,
        }


@dataclass
class ConfigInfo:
    """Application configuration (sanitized)."""
    config_files: list[str] = field(default_factory=list)
    key_settings: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "config_files": self.config_files,
            "key_settings": self.key_settings,
        }


# ---------------------------------------------------------------------------
# Top-level context
# ---------------------------------------------------------------------------

@dataclass
class AnalysisContext:
    """Root context object — all collectors fill their sections."""
    dump_path: str = ""
    exe_dir: Optional[str] = None
    source_dir: Optional[str] = None
    log_dir: Optional[str] = None
    symbol_paths: list[str] = field(default_factory=list)
    collected_at: str = ""

    dmp: DmpData = field(default_factory=DmpData)
    binaries: Optional[BinaryInfo] = None
    symbols: Optional[SymbolInfo] = None
    logs: Optional[LogInfo] = None
    system_events: Optional[SystemEventInfo] = None
    source: Optional[SourceInfo] = None
    config: Optional[ConfigInfo] = None

    def to_dict(self) -> dict:
        result: dict = {
            "meta": {
                "dump_path": self.dump_path,
                "exe_dir": self.exe_dir,
                "source_dir": self.source_dir,
                "log_dir": self.log_dir,
                "symbol_paths": self.symbol_paths,
                "collected_at": self.collected_at,
            },
            "dmp": self.dmp.to_dict(),
        }
        for key in ("binaries", "symbols", "logs", "system_events", "source", "config"):
            val = getattr(self, key)
            if val is not None:
                result[key] = val.to_dict()
        return result
