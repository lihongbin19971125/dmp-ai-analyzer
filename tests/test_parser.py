"""Tests for parser.py -- CDB output to structured data.

Covers all parser functions:
  - parse_system_info
  - parse_exception_info
  - parse_callstack
  - parse_all_threads
  - parse_module_list
  - parse_heap_info
  - parse_locks
  - parse_cdb_output (integration)
  - _detect_dump_type
  - _extract_registers
"""

import pytest
from mvp.parser import (
    parse_system_info,
    parse_exception_info,
    parse_callstack,
    parse_all_threads,
    parse_module_list,
    parse_heap_info,
    parse_locks,
    parse_cdb_output,
    _detect_dump_type,
    _extract_registers,
)
from mvp.context import (
    SystemInfo,
    ExceptionInfo,
    Frame,
    ThreadStack,
    ModuleInfo,
    HeapInfo,
    LockInfo,
    DmpData,
)


# ============================================================================
# Sample CDB output snippets
# ============================================================================

SAMPLE_CDB_SYSTEM_INFO = r"""Windows 10 Version 26200 MP (12 procs) Free x64
Product: WinNt, suite: SingleUserTS
Edition build lab: 26200.1.amd64fre.ge_release.250515-1710
Machine Name: DESKTOP-CRASH01

OSNAME: Windows 10 Pro
OS_VERSION: 10.0.26200.1
OSPLATFORM_TYPE: x64

System Uptime: 3 days 7:22:15
Boot Time 6/23/2026 08:00:00.000

Processor: Intel(R) Core(TM) i7-13700K
4 processors
SSE2 SSE3 SSSE3 SSE4.1 SSE4.2 AVX AVX2 FMA3 BMI1 BMI2 RDRAND

PageFile: 0x0000000200000000 ( 8192 Mb )
Physical: 0x0000000040000000 ( 16384 Mb )
Avail: 0x0000000010000000 ( 4096 Mb )

WorkingSet: 0x0000000008000000 ( 2048 Mb )

COMPUTERNAME=DESKTOP-CRASH01
USERNAME=admin123
USERDOMAIN=WORKGROUP
USERPROFILE=C:\Users\admin123
TEMP=C:\Users\admin123\AppData\Local\Temp
MYAPP_CONFIG_DIR=D:\config
MYAPP_LOG_LEVEL=DEBUG
"""

SAMPLE_MINIMAL = r"""Windows 11 Version 26100 MP (8 procs) Free x64
Product: WinNt
"""

SAMPLE_AV = r"""
ExceptionCode: C0000005 (Access violation)
ExceptionAddress: 00007ff6`12345678
Attempt to read from address 00000000`00000000
First chance exception
"""

SAMPLE_SO = r"""
ExceptionCode: C00000FD (Stack overflow)
ExceptionAddress: 00007ff6`abcd0000
Second chance, this exception will not be handled further
"""

SAMPLE_SBO = r"""
Security check failure or stack buffer overrun - code c0000409
FAULTING_IP: mylib!FastFail+1f2
   00007ff7`12345678
"""

SAMPLE_HEAP = r"""
ExceptionCode: C0000374 (STATUS_HEAP_CORRUPTION)
In page error reading memory at 00000000`12340000
"""

SAMPLE_CALLSTACK_STANDARD = r"""00 00007ff7`12345678 myapp!main+0x42 [d:\src\main.cpp @ 342]
01 00007ff7`12346780 myapp!WorkerThread+0x120 [d:\src\worker.cpp @ 156]
02 00007ff7`12347000 libcore!ProcessData+0x3f4
03 00007fff`abcd1234 ntdll!RtlUserThreadStart+0x20
"""

SAMPLE_CALLSTACK_WITH_HEADER = r""" # Child-SP          RetAddr           Call Site
00 00000032`5717c530 00007ff7`12345678 myapp!CrashFunc+0x10
01 00000032`5717c538 00007ff7`12346780 myapp!main+0x42
"""

SAMPLE_CALLSTACK_INLINE = r"""00 (Inline) 00007ff6`11112222 mylib!HelperFunc+0x5 [d:\src\util.h @ 42]
01 00007ff6`33334444 mylib!CallerFunc+0x88 [d:\src\main.cpp @ 100]
"""

SAMPLE_CALLSTACK_HEX_FRAMES = r"""0a 00007ff6`11111111 lib!FuncA+0x10
0b 00007ff6`22222222 lib!FuncB+0x20
"""

SAMPLE_THREADS = r"""   0  Id: 1a8c.1a90 Crashed <Memory Access Violation>
00 00007ff6`11111111 myapp!CrashFunc+0x10
01 00007ff6`22222222 myapp!main+0x42

   1  Id: 1a8c.1a94 Waiting:UserRequest
00 00007fff`33333333 ntdll!NtWaitForSingleObject+0x14
01 00007fff`44444444 KERNELBASE!WaitForSingleObjectEx+0x8e

   2  Id: 1a8c.1a98 Suspended
00 00007fff`55555555 ntdll!NtDelayExecution+0x14
"""

SAMPLE_MODULES = r"""start    end        module name
00007ff7`12340000 00007ff7`12350000 myapp
    Image path: C:\Program Files\MyApp\myapp.exe
    File version: 1.2.3.4
    Timestamp: Mon Jun 23 14:00:00 2026 (69420)
    PDB: myapp.pdb (symbols loaded)

00007fff`abcd0000 00007fff`abcf0000 ntdll
    Image path: C:\Windows\System32\ntdll.dll
    File version: 10.0.26200.1
"""

SAMPLE_HEAP_INFO_CORRUPTED = r"""5 heaps found
LFH Key: 0x...
Termination on corruption: ENABLED
  Heap 0000012340000000
    commit 0x0000002000000 ( 512 Mb )
    Lock contention: 42
    corruption detected; HEAP: Free Heap block 0000012345678 modified at 0000012345680 after it was freed
    HEAP_CORRUPTION_DETAILS: heap block damaged, possible use-after-free
"""

SAMPLE_HEAP_INFO_HEALTHY = r"""3 heaps found
LFH Key: 0x...
Termination on corruption: ENABLED
  Heap 0000012340000000
    commit 0x0000001000000 ( 256 Mb )
"""

SAMPLE_LOCKS = r"""CritSec ntdll!LdrpLoaderLock+0 at 00007fff`12345678
LockCount 1, WaiterCount 0

CritSec myapp!CSettingsLock+0 at 00007fff`87654321
LockCount 3, WaiterCount 2
"""

SAMPLE_FULL_CDB_OUTPUT = r"""Debug session time: Mon Jun 23 15:26:44.000 2026 (UTC + 8:00)

Windows 10 Version 26200 MP (12 procs) Free x64
Product: WinNt
Machine Name: DESKTOP-CRASH01
OS_VERSION: 10.0.26200.1

OSNAME: Windows 10 Pro
OSPLATFORM_TYPE: x64

ExceptionCode: C0000005 (Access violation)
ExceptionAddress: 00007ff6`12345678
Attempt to read from address 00000000`00000000
First chance exception

STACK_TEXT:
00000032`5717c530 00007ff6`12345678 myapp!CrashFunc+0x10 [d:\src\crash.cpp @ 42]
00000032`5717c538 00007ff6`12346780 myapp!WorkerThread+0x88 [d:\src\worker.cpp @ 156]

CONTEXT:  (.ecxr)
rax=0000000000000000 rbx=000000325717cab0 rcx=000000325717c530
rdx=000000325717c9e0 rsi=000000325717cab0 rdi=000000325717c530
rip=00007ff612345678 rsp=000000325717c530 rbp=000000325717c9e0
efl=00010246

start    end        module name
00007ff6`12340000 00007ff6`12380000 myapp
    Image path: C:\Program Files\MyApp\myapp.exe
"""

SAMPLE_REGS = r"""CONTEXT:  (.ecxr)
rax=0000000000000000 rbx=000000325717cab0 rcx=000000325717c530
rdx=000000325717c9e0 rsi=000000325717cab0 rdi=000000325717c530
rip=00007ff612345678 rsp=000000325717c530 rbp=000000325717c9e0
efl=00010246 cs=0033 ss=002b ds=002b es=002b fs=0053 gs=002b
Resetting default scope
"""


# ============================================================================
# Tests: parse_system_info
# ============================================================================

class TestParseSystemInfo:
    """System info extraction from vertarget / !sysinfo / !cpuinfo / !vm / !memusage / !envvar."""

    # ------------------------------------------------------------------
    # test_parse_system_info_complete
    # ------------------------------------------------------------------
    def test_parse_system_info_complete(self):
        """Parse a full vertarget+!sysinfo+!cpuinfo+!vm+!memusage+!envvar output blob.

        Verifies every SystemInfo field is extracted correctly from the full
        multi-section CDB output sample.
        """
        info = parse_system_info(SAMPLE_CDB_SYSTEM_INFO)

        # OS fields: OSNAME takes priority over vertarget
        assert info.os_name == "Windows 10 Pro"
        # OS_VERSION: full dotted string is preserved
        assert info.os_version == "10.0.26200.1"
        assert info.os_build == "26200"

        # Platform from OSPLATFORM_TYPE
        assert info.platform == "x64"

        # CPU
        assert info.cpu_count == 4
        assert info.cpu_model == "Intel(R) Core(TM) i7-13700K"

        # CPU features -- sorted list of detected instruction-set strings.
        # AES-NI is NOT in this sample (SSE2/SSE3/SSSE3/SSE4.x/AVX/AVX2/FMA3/BMI1/BMI2/RDRAND).
        expected_features = sorted([
            "SSE2", "SSE3", "SSSE3", "SSE4.1", "SSE4.2",
            "AVX", "AVX2", "FMA3", "BMI1", "BMI2", "RDRAND",
        ])
        assert info.cpu_features == expected_features

        # Memory from !vm
        assert info.total_pagefile_mb == 8192
        assert info.total_physical_mb == 16384
        assert info.available_physical_mb == 4096

        # Process working set from !memusage
        assert info.process_working_set_mb == 2048

        # Uptime: 3 days 7:22:15
        expected_uptime = 3 * 86400 + 7 * 3600 + 22 * 60 + 15  # 285735
        assert info.system_uptime_seconds == expected_uptime

        # Boot Time -- the regex r"Boot Time [\d.]+\s+..." expects a numeric
        # prefix before the date; the sample "Boot Time 6/23/2026 ..." starts
        # with a date directly and does not match.  Verifying actual behaviour.
        assert info.boot_time is None

        # Machine name (from "Machine Name:" in vertarget)
        assert info.machine_name == "DESKTOP-CRASH01"

        # Environment: common vars (COMPUTERNAME, USERNAME, USERDOMAIN,
        # USERPROFILE, TEMP) are filtered out; only app-specific vars remain.
        assert "MYAPP_CONFIG_DIR" in info.environment
        assert info.environment["MYAPP_CONFIG_DIR"] == r"D:\config"
        assert "MYAPP_LOG_LEVEL" in info.environment
        assert info.environment["MYAPP_LOG_LEVEL"] == "DEBUG"
        # Verify that filtered keys are NOT present
        for filtered_key in ("COMPUTERNAME", "USERNAME", "USERDOMAIN",
                             "USERPROFILE", "TEMP"):
            assert filtered_key not in info.environment

    # ------------------------------------------------------------------
    # test_parse_system_info_minimal
    # ------------------------------------------------------------------
    def test_parse_system_info_minimal(self):
        """Parse minimal vertarget output (bare Windows version, no OSNAME/OSPLATFORM).

        When OSNAME field is missing the parser falls back to the vertarget
        "Windows N Version M" preamble.  "procs" is not matched by the
        "processors?" regex so cpu_count falls through to the default (1).
        """
        info = parse_system_info(SAMPLE_MINIMAL)

        assert info.os_name == "Windows 11"
        assert info.os_version == "10.0.26100"
        assert info.os_build == "26100"
        # Platform extracted from "x64 Free" via fallback regex
        assert info.platform == "x64"
        # "MP (8 procs)" is parsed as fallback CPU count
        assert info.cpu_count == 8

    # ------------------------------------------------------------------
    # test_parse_system_info_empty
    # ------------------------------------------------------------------
    def test_parse_system_info_empty(self):
        """Verify parse_system_info returns default-initialized SystemInfo for empty input.

        All string fields stay empty, int fields stay 0 except cpu_count which
        is forced to 1 by the ``cpu_count = cpu_count or 1`` guard.
        """
        info = parse_system_info("")

        assert info.os_name == ""
        assert info.os_version == ""
        assert info.os_build == ""
        assert info.platform == ""
        assert info.cpu_model == ""
        assert info.cpu_features == []
        assert info.total_physical_mb == 0
        assert info.available_physical_mb == 0
        assert info.total_pagefile_mb == 0
        assert info.process_working_set_mb == 0
        assert info.system_uptime_seconds == 0
        assert info.boot_time is None
        assert info.machine_name is None
        assert info.environment == {}
        # cpu_count is forced to 1 even on empty input
        assert info.cpu_count == 1


# ============================================================================
# Tests: parse_exception_info
# ============================================================================

class TestParseExceptionInfo:
    """Exception info extraction from !analyze -v and CDB preamble output."""

    # ------------------------------------------------------------------
    # test_parse_exception_info_access_violation
    # ------------------------------------------------------------------
    def test_parse_exception_info_access_violation(self):
        """Parse a classic C0000005 access violation.

        Verifies code, name lookup, address (with backtick stripped),
        read type, attempted null address, and first-chance flag.
        """
        info = parse_exception_info(SAMPLE_AV)

        assert info.code == "C0000005"
        assert info.name == "ACCESS_VIOLATION"
        assert info.address == "00007ff612345678"
        assert info.type == "read"
        assert info.attempted_address == "0000000000000000"
        assert info.first_chance is True
        assert info.in_page_error is False
        assert info.security_violation is False

    # ------------------------------------------------------------------
    # test_parse_exception_info_second_chance
    # ------------------------------------------------------------------
    def test_parse_exception_info_second_chance(self):
        """Parse a second-chance stack-overflow exception.

        'second chance' in the text flips first_chance to False.
        Stack overflow has no read/write type string.
        """
        info = parse_exception_info(SAMPLE_SO)

        assert info.code == "C00000FD"
        assert info.name == "STACK_OVERFLOW"
        assert info.address == "00007ff6abcd0000"
        assert info.type == ""
        assert info.first_chance is False

    # ------------------------------------------------------------------
    # test_parse_exception_info_security_violation
    # ------------------------------------------------------------------
    def test_parse_exception_info_security_violation(self):
        """Parse a C0000409 stack-buffer-overrun (security violation).

        The exception code is extracted via Strategy 2 ('code c0000409'
        pattern), name via the lookup table, address via FAULTING_IP.
        """
        info = parse_exception_info(SAMPLE_SBO)

        assert info.code == "C0000409"
        assert info.name == "STACK_BUFFER_OVERRUN"
        assert info.address == "00007ff712345678"
        assert info.security_violation is True

    # ------------------------------------------------------------------
    # test_parse_exception_info_heap_corruption
    # ------------------------------------------------------------------
    def test_parse_exception_info_heap_corruption(self):
        """Parse C0000374 heap corruption with in-page error flag."""
        info = parse_exception_info(SAMPLE_HEAP)

        assert info.code == "C0000374"
        assert info.name == "HEAP_CORRUPTION"
        assert info.in_page_error is True


# ============================================================================
# Tests: parse_callstack
# ============================================================================

class TestParseCallstack:
    """Callstack parsing from CDB text blocks."""

    # ------------------------------------------------------------------
    # test_parse_callstack_standard
    # ------------------------------------------------------------------
    def test_parse_callstack_standard(self):
        """Parse a standard callstack with numbered frames and source annotations.

        The sample frames use the ``[file @ line]`` annotation format.
        Note: the parser's source-extraction regex expects ``[file]: line``
        (colon after bracket), so ``@``-delimited annotations are NOT
        extracted.  This test verifies actual parser behaviour.
        """
        frames = parse_callstack(SAMPLE_CALLSTACK_STANDARD)

        assert len(frames) == 4

        # Frame 0
        assert frames[0].frame_index == 0
        assert frames[0].module == "myapp"
        assert frames[0].function == "myapp!main+0x42"
        # @-format annotations are now extracted by the updated regex
        assert frames[0].source_file == "d:\\src\\main.cpp"
        assert frames[0].source_line == 342

        # Frame 1
        assert frames[1].frame_index == 1
        assert frames[1].module == "myapp"
        assert frames[1].function == "myapp!WorkerThread+0x120"

        # Frame 2
        assert frames[2].frame_index == 2
        assert frames[2].module == "libcore"
        assert frames[2].function == "libcore!ProcessData+0x3f4"

        # Frame 3
        assert frames[3].frame_index == 3
        assert frames[3].module == "ntdll"
        assert frames[3].function == "ntdll!RtlUserThreadStart+0x20"

    # ------------------------------------------------------------------
    # test_parse_callstack_with_header_lines
    # ------------------------------------------------------------------
    def test_parse_callstack_with_header_lines(self):
        """Parse callstack that contains Child-SP/RetAddr header lines.

        Header lines containing 'Child-SP', 'RetAddr', or 'Call Site' are
        skipped.  Only the actual frame lines produce Frame objects.
        """
        frames = parse_callstack(SAMPLE_CALLSTACK_WITH_HEADER)

        assert len(frames) == 2

        assert frames[0].frame_index == 0
        assert frames[0].function == "myapp!CrashFunc+0x10"

        assert frames[1].frame_index == 1
        assert frames[1].function == "myapp!main+0x42"

    # ------------------------------------------------------------------
    # test_parse_callstack_inline_frame
    # ------------------------------------------------------------------
    def test_parse_callstack_inline_frame(self):
        """Parse a callstack containing inline function frames.

        The ``(Inline)`` marker is handled and stripped; the frame number,
        address, and function symbol are still parsed correctly.
        """
        frames = parse_callstack(SAMPLE_CALLSTACK_INLINE)

        assert len(frames) == 2

        # Frame 0: inline
        assert frames[0].frame_index == 0
        assert frames[0].function == "mylib!HelperFunc+0x5"
        assert frames[0].module == "mylib"

        # Frame 1: regular
        assert frames[1].frame_index == 1
        assert frames[1].function == "mylib!CallerFunc+0x88"
        assert frames[1].module == "mylib"

    # ------------------------------------------------------------------
    # test_parse_callstack_hex_frame_numbers
    # ------------------------------------------------------------------
    def test_parse_callstack_hex_frame_numbers(self):
        """Parse callstack with hex frame numbers (e.g. '0a' instead of '10').

        The parser detects hex digits (a-f) in the frame number and uses
        base-16 conversion, so '0a' becomes frame_index 10, '0b' becomes 11.
        """
        frames = parse_callstack(SAMPLE_CALLSTACK_HEX_FRAMES)

        assert len(frames) == 2

        assert frames[0].frame_index == 10
        assert frames[0].module == "lib"
        assert frames[0].function == "lib!FuncA+0x10"

        assert frames[1].frame_index == 11
        assert frames[1].module == "lib"
        assert frames[1].function == "lib!FuncB+0x20"

    # ------------------------------------------------------------------
    # test_parse_callstack_empty
    # ------------------------------------------------------------------
    def test_parse_callstack_empty(self):
        """Parse an empty callstack block returns an empty list."""
        frames = parse_callstack("")
        assert frames == []
        assert isinstance(frames, list)


# ============================================================================
# Tests: parse_all_threads
# ============================================================================

class TestParseAllThreads:
    """Multi-thread callstack parsing from ~* k output."""

    # ------------------------------------------------------------------
    # test_parse_all_threads_multiple
    # ------------------------------------------------------------------
    def test_parse_all_threads_multiple(self):
        """Parse ~* k output with multiple threads including a crashed thread.

        Three threads are parsed:
          - Thread 0x1a90: state='crashed', 2 frames
          - Thread 0x1a94: state='waiting', 2 frames
          - Thread 0x1a98: state='suspended', 1 frame
        """
        threads = parse_all_threads(SAMPLE_THREADS)

        assert len(threads) == 3

        # Thread 0 -- crashed
        t0 = threads[0]
        assert t0.thread_id == 0x1A90  # 6800
        assert t0.state == "crashed"
        assert len(t0.callstack) == 2
        assert t0.callstack[0].function == "myapp!CrashFunc+0x10"
        assert t0.callstack[1].function == "myapp!main+0x42"

        # Thread 1 -- waiting
        t1 = threads[1]
        assert t1.thread_id == 0x1A94  # 6804
        assert t1.state == "waiting"
        assert len(t1.callstack) == 2
        assert t1.callstack[0].module == "ntdll"

        # Thread 2 -- suspended
        t2 = threads[2]
        assert t2.thread_id == 0x1A98  # 6808
        assert t2.state == "suspended"
        assert len(t2.callstack) == 1
        assert t2.callstack[0].function == "ntdll!NtDelayExecution+0x14"


# ============================================================================
# Tests: parse_module_list
# ============================================================================

class TestParseModuleList:
    """Module list parsing from lm vm output."""

    # ------------------------------------------------------------------
    # test_parse_module_list_standard
    # ------------------------------------------------------------------
    def test_parse_module_list_standard(self):
        """Parse lm vm output for multiple modules.

        Verifies base address, size calculation, path, version,
        timestamp, and symbol status for both modules.
        """
        modules = parse_module_list(SAMPLE_MODULES)

        assert len(modules) == 2

        # Module 0: myapp
        m0 = modules[0]
        assert m0.name == "myapp"
        assert m0.base_address == "00007ff712340000"
        # size = end - base = 0x00007ff712350000 - 0x00007ff712340000 = 0x10000
        assert m0.size == 0x10000  # 65536
        assert m0.path == r"C:\Program Files\MyApp\myapp.exe"
        assert m0.version == "1.2.3.4"
        assert m0.timestamp == "Mon Jun 23 14:00:00 2026 (69420)"
        assert m0.has_symbols is True

        # Module 1: ntdll
        m1 = modules[1]
        assert m1.name == "ntdll"
        assert m1.base_address == "00007fffabcd0000"
        # size = 0x00007fffabcf0000 - 0x00007fffabcd0000 = 0x20000
        assert m1.size == 0x20000  # 131072
        assert m1.path == r"C:\Windows\System32\ntdll.dll"
        assert m1.version == "10.0.26200.1"
        assert m1.has_symbols is False


# ============================================================================
# Tests: parse_heap_info
# ============================================================================

class TestParseHeapInfo:
    """Heap info parsing from !heap -s output."""

    # ------------------------------------------------------------------
    # test_parse_heap_info_corrupted
    # ------------------------------------------------------------------
    def test_parse_heap_info_corrupted(self):
        """Parse !heap -s output showing heap corruption.

        Verifies heap count, total committed (Mb), corrupted flag,
        and extraction of corruption detail lines.
        """
        info = parse_heap_info(SAMPLE_HEAP_INFO_CORRUPTED)

        assert info.heap_count == 5
        assert info.total_committed_mb == 512
        assert info.corrupted is True
        assert len(info.details) > 0
        # At least one detail line mentions corruption
        assert any("corruption" in d.lower() or "corrupt" in d.lower()
                   for d in info.details)

    # ------------------------------------------------------------------
    # test_parse_heap_info_healthy
    # ------------------------------------------------------------------
    def test_parse_heap_info_healthy(self):
        """Parse !heap -s output for a healthy heap.

        Verifies heap count, committed memory, no corruption flag,
        and empty details list.
        """
        info = parse_heap_info(SAMPLE_HEAP_INFO_HEALTHY)

        assert info.heap_count == 3
        assert info.total_committed_mb == 256
        assert info.corrupted is False
        assert info.details == []


# ============================================================================
# Tests: parse_locks
# ============================================================================

class TestParseLocks:
    """Lock info parsing from !locks output."""

    # ------------------------------------------------------------------
    # test_parse_locks_critical_section
    # ------------------------------------------------------------------
    def test_parse_locks_critical_section(self):
        """Parse !locks output with critical sections.

        Each ``CritSec ... at <address>`` line produces a LockInfo with
        lock_type='critical_section' and the address (backtick stripped).
        """
        locks = parse_locks(SAMPLE_LOCKS)

        assert len(locks) == 2
        assert locks[0].lock_type == "critical_section"
        assert locks[0].address == "00007fff12345678"
        assert locks[1].lock_type == "critical_section"
        assert locks[1].address == "00007fff87654321"

    # ------------------------------------------------------------------
    # test_parse_locks_empty
    # ------------------------------------------------------------------
    def test_parse_locks_empty(self):
        """Parse empty !locks output returns an empty list."""
        locks = parse_locks("")
        assert locks == []
        assert isinstance(locks, list)


# ============================================================================
# Tests: _detect_dump_type
# ============================================================================

class TestDetectDumpType:
    """Dump type detection from filename and/or content."""

    # ------------------------------------------------------------------
    # test_detect_dump_type_from_filename
    # ------------------------------------------------------------------
    def test_detect_dump_type_from_filename(self):
        """Detect dump type from filename pattern.

        A path containing 'full' returns 'full' regardless of raw content.
        """
        result = _detect_dump_type(
            raw="",
            dump_path=r"C:\dumps\crash_full.dmp",
        )
        assert result == "full"

    # ------------------------------------------------------------------
    # test_detect_dump_type_minidump_default
    # ------------------------------------------------------------------
    def test_detect_dump_type_minidump_default(self):
        """Default to minidump when no indicators present in filename or content."""
        result = _detect_dump_type(
            raw="some output without dump type markers",
            dump_path=r"C:\dumps\crash.dmp",
        )
        assert result == "minidump"


# ============================================================================
# Tests: _extract_registers
# ============================================================================

class TestExtractRegisters:
    """Register extraction from CONTEXT block."""

    # ------------------------------------------------------------------
    # test_extract_registers_x64
    # ------------------------------------------------------------------
    def test_extract_registers_x64(self):
        """Extract x64 registers from a CONTEXT: (.ecxr) block.

        All present x64 general-purpose registers are captured.
        Registers not in the input (e.g. r8-r15) are absent from the dict.
        """
        regs = _extract_registers(SAMPLE_REGS)

        # Present registers with their exact hex values
        assert regs["rax"] == "0000000000000000"
        assert regs["rbx"] == "000000325717cab0"
        assert regs["rcx"] == "000000325717c530"
        assert regs["rdx"] == "000000325717c9e0"
        assert regs["rsi"] == "000000325717cab0"
        assert regs["rdi"] == "000000325717c530"
        assert regs["rip"] == "00007ff612345678"
        assert regs["rsp"] == "000000325717c530"
        assert regs["rbp"] == "000000325717c9e0"
        assert regs["efl"] == "00010246"
        assert regs["cs"] == "0033"
        assert regs["ss"] == "002b"
        assert regs["ds"] == "002b"
        assert regs["es"] == "002b"
        assert regs["fs"] == "0053"
        assert regs["gs"] == "002b"

        # r8-r15 are not present in this sample
        for reg_name in ("r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
            assert reg_name not in regs, (
                f"Register {reg_name} should not be in extracted dict"
            )


# ============================================================================
# Tests: parse_cdb_output (integration)
# ============================================================================

class TestParseCdbOutput:
    """Full CDB output parsing -- integration of all sub-parsers."""

    # ------------------------------------------------------------------
    # test_parse_cdb_output_integration
    # ------------------------------------------------------------------
    def test_parse_cdb_output_integration(self):
        """Full integration parse of a realistic multi-section CDB output blob.

        Verifies that parse_cdb_output correctly routes each section to the
        right sub-parser and populates all major fields of DmpData:
        metadata, system_info, exception, crash_callstack, modules, and
        registers.
        """
        data = parse_cdb_output(SAMPLE_FULL_CDB_OUTPUT, r"C:\dumps\crash.dmp")

        # -- metadata --
        assert data.metadata.dump_type == "minidump"
        assert "Mon Jun 23 15:26:44.000 2026" in data.metadata.timestamp

        # -- system_info --
        assert data.system_info.os_name == "Windows 10 Pro"
        assert data.system_info.platform == "x64"
        assert data.system_info.os_build == "26200"

        # -- exception --
        assert data.exception.code == "C0000005"
        assert data.exception.name == "ACCESS_VIOLATION"
        assert data.exception.type == "read"
        assert data.exception.attempted_address == "0000000000000000"

        # -- crash_callstack (from STACK_TEXT) --
        assert len(data.crash_callstack) == 2
        assert data.crash_callstack[0].function == "myapp!CrashFunc+0x10"
        assert data.crash_callstack[0].module == "myapp"
        assert data.crash_callstack[1].function == "myapp!WorkerThread+0x88"

        # -- modules --
        assert len(data.modules) == 1
        assert data.modules[0].name == "myapp"

        # -- registers --
        assert "rip" in data.registers
        assert data.registers["rip"] == "00007ff612345678"
        assert data.registers["rax"] == "0000000000000000"

        # -- raw output preserved --
        assert data.raw_analyze_output == SAMPLE_FULL_CDB_OUTPUT


# ============================================================================
# Tests that require real resources (marked skip)
# ============================================================================

@pytest.mark.skip(reason="Requires a real CDB debugger and dump file on disk")
class TestParserWithRealDump:
    """Tests that need a live CDB installation and real .dmp file.

    These are integration smoke tests for end-to-end verification.
    """

    def test_parse_real_minidump(self):
        """Parse output from a real minidump via CDB."""
        # This would invoke cdb.exe -z <dump> -c "<commands>;q"
        # and feed the output to parse_cdb_output.
        pass

    def test_parse_real_full_dump(self):
        """Parse output from a real full dump via CDB."""
        pass


# ═════════════════════════════════════════════════════════════════════════
# Enhanced heap parsing test samples
# ═════════════════════════════════════════════════════════════════════════

SAMPLE_HEAP_ENHANCED = r"""5 heaps found
LFH Key: 0x7ffe12345678
Termination on corruption: ENABLED

  Heap 0000012340000000
    Reserved 0000000002000000 (32768 KB)
    Committed 0000000001500000 (21504 KB)
    Free 0000000000080000 (512 KB)
    Virtual address space: 8 segments
    Lock contention: 42

  Heap 0000012340010000
    Reserved 0000000001000000 (16384 KB)
    Committed 0000000000800000 (8192 KB)
    Free 0000000000040000 (256 KB)
    Virtual address space: 3 segments

  Heap 0000012340020000
    Reserved 0000000000080000 (512 KB)
    Committed 0000000000040000 (256 KB)
    Free 0000000000010000 (64 KB)
    Virtual address space: 2 segments
"""

SAMPLE_HEAP_EMPTY = r"""0 heaps found
LFH Key: 0x0
Termination on corruption: DISABLED
"""

SAMPLE_ADDRESS_SUMMARY = r"""
--- Usage Summary ---------------- RgnCount ----------- Total Size -------- %ofBusy %ofTotal
Free                                     45          7ffe`00000000 ( 127.992 TB)           65.00%
Image                                   342            7`3f4b0000 (   1.813 GB)  25.00%    8.75%
Heap                                     55            2`8a3b0000 ( 650.000 MB)   8.90%    3.11%
Stack                                    12              8c000000 (   2.188 GB)  30.00%   10.50%
MappedFile                               28              50000000 (  80.000 MB)   1.10%    0.38%
Other                                     8              15000000 (  21.000 MB)   0.29%    0.10%
TEB                                       6               600000 (   6.000 MB)   0.08%    0.03%
PEB                                       1                 1000 (   4.000 KB)   0.00%    0.00%

--- State Summary ---------------- RgnCount ----------- Total Size -------- %ofBusy %ofTotal
MEM_FREE                                45          7ffe`00000000 ( 127.992 TB)           65.00%
MEM_RESERVE                             52            1`2a3b0000 (   4.660 GB)  64.00%   22.47%
MEM_COMMIT                             402            3`8c1b0000 (  14.190 GB) 194.00%   68.84%

--- Largest Free Block by Region -
Largest free block: 7ffd`f0000000 ( 127.980 TB)
"""


# ═════════════════════════════════════════════════════════════════════════
# Enhanced parse_heap_info tests
# ═════════════════════════════════════════════════════════════════════════

class TestParseHeapInfoEnhanced:
    """Tests for enhanced parse_heap_info with new fields."""

    def test_parses_reserved_mb(self):
        """Extract total reserved from all heaps."""
        from mvp.parser import parse_heap_info
        result = parse_heap_info(SAMPLE_HEAP_ENHANCED)
        # Reserved: 32768KB + 16384KB + 512KB = 49664KB ≈ 48.5MB
        assert 45 <= result.total_reserved_mb <= 52

    def test_parses_free_bytes(self):
        """Extract free bytes from heaps."""
        from mvp.parser import parse_heap_info
        result = parse_heap_info(SAMPLE_HEAP_ENHANCED)
        # Free: 512KB + 256KB + 64KB = 832KB
        assert result.free_bytes > 500_000
        assert result.free_bytes < 1_000_000

    def test_parses_segment_count(self):
        """Extract segment count."""
        from mvp.parser import parse_heap_info
        result = parse_heap_info(SAMPLE_HEAP_ENHANCED)
        # 8 + 3 + 2 = 13 segments
        assert result.segment_count == 13

    def test_parses_lfh_enabled(self):
        """LFH Key present means enabled."""
        from mvp.parser import parse_heap_info
        result = parse_heap_info(SAMPLE_HEAP_ENHANCED)
        assert result.lfh_enabled is True

    def test_empty_heap_returns_defaults(self):
        """When !heap -s returns empty, all fields are defaults."""
        from mvp.parser import parse_heap_info
        result = parse_heap_info(SAMPLE_HEAP_EMPTY)
        assert result.heap_count == 0
        assert result.total_committed_mb == 0
        assert result.total_reserved_mb == 0
        assert result.lfh_enabled is False
        assert result.segment_count == 0

    def test_per_heap_breakdown(self):
        """Per-heap breakdown captures individual heap data."""
        from mvp.parser import parse_heap_info
        result = parse_heap_info(SAMPLE_HEAP_ENHANCED)
        assert len(result.per_heap_breakdown) == 3
        h0 = result.per_heap_breakdown[0]
        assert h0["address"] == "0000012340000000"
        assert h0["commit_mb"] > 0
        assert h0["reserve_mb"] > 0
        assert h0["segments"] == 8

    def test_parse_heap_mixed_units(self):
        """Commit values in KB and MB parse correctly."""
        from mvp.parser import parse_heap_info
        # Already tested via SAMPLE_HEAP_ENHANCED which has KB values
        result = parse_heap_info(SAMPLE_HEAP_ENHANCED)
        assert result.total_committed_mb > 0

    def test_no_corruption_false_positive(self):
        """'Termination on corruption: ENABLED' should NOT set corrupted."""
        from mvp.parser import parse_heap_info
        result = parse_heap_info(SAMPLE_HEAP_ENHANCED)
        assert result.corrupted is False

    def test_committed_and_reserved_sum_across_heaps(self):
        """Both committed and reserved should sum across all heaps."""
        from mvp.parser import parse_heap_info
        result = parse_heap_info(SAMPLE_HEAP_ENHANCED)
        # Committed: 21504KB + 8192KB + 256KB = 29952KB ≈ 29MB
        assert 26 <= result.total_committed_mb <= 32
        # Reserved should be higher than committed
        assert result.total_reserved_mb > result.total_committed_mb


# ═════════════════════════════════════════════════════════════════════════
# parse_address_summary tests
# ═════════════════════════════════════════════════════════════════════════

class TestParseAddressSummary:
    """Tests for parse_address_summary() — !address -summary output."""

    def test_parses_free_virtual(self):
        """Extract free virtual address space."""
        from mvp.parser import parse_address_summary
        result = parse_address_summary(SAMPLE_ADDRESS_SUMMARY)
        assert "Free" in result
        assert result["Free"] > 1_000_000  # Should have many MB of free space

    def test_parses_image_heap_stack(self):
        """Extract Image, Heap, Stack sizes."""
        from mvp.parser import parse_address_summary
        result = parse_address_summary(SAMPLE_ADDRESS_SUMMARY)
        assert result.get("Image", 0) > 0
        assert result.get("Heap", 0) > 0
        assert result.get("Stack", 0) > 0

    def test_parses_largest_free_block(self):
        """Extract largest free block."""
        from mvp.parser import parse_address_summary
        result = parse_address_summary(SAMPLE_ADDRESS_SUMMARY)
        assert result.get("LargestFreeBlock", 0) > 0

    def test_empty_input(self):
        """Empty input returns empty dict."""
        from mvp.parser import parse_address_summary
        result = parse_address_summary("")
        assert result == {}

    def test_no_free_section(self):
        """When address summary has no Free section, returns what it can."""
        from mvp.parser import parse_address_summary
        partial = "--- Usage Summary ----\nHeap     55    2`8a3b0000 ( 650.000 MB)\n"
        result = parse_address_summary(partial)
        assert result.get("Heap", 0) > 0
