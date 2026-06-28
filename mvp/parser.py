"""Parser for CDB debugger output.

Converts raw CDB text output into structured Python dataclass instances
defined in context.py.

CDB output is semi-structured multi-line text. This module uses a
combination of section delimiters, regex patterns, and line-by-line
state machines to extract structured data.
"""

import re
from datetime import datetime
from typing import Optional

from .context import (
    DmpData,
    DmpMetadata,
    ExceptionInfo,
    Frame,
    HeapInfo,
    LockInfo,
    ModuleInfo,
    SystemInfo,
    ThreadStack,
)


# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------

def parse_system_info(raw: str) -> SystemInfo:
    """Extract system information from CDB output.

    Parses output from: vertarget, !sysinfo, !cpuinfo, !vm, !memusage, !envvar
    """
    info = SystemInfo()

    # --- OS version (from multiple sources) ---
    # Source 1: OS_VERSION: 10.0.26100.1 (from !analyze -v)
    m = re.search(r"OS_VERSION:\s*(\d+)\.(\d+)\.([\d.]+)", raw)
    if m:
        info.os_version = f"{m.group(1)}.{m.group(2)}.{m.group(3)}"
        parts = m.group(3).split(".")
        info.os_build = parts[0]

    # Source 2: OSNAME: Windows 10 (from !analyze -v)
    m = re.search(r"OSNAME:\s*(\S.+)", raw)
    if m:
        info.os_name = m.group(1).strip()

    # Source 3: "Windows 10 Version 26200 MP ..." (from vertarget preamble)
    if not info.os_name:
        m = re.search(r"Windows\s+(\S+)\s+Version\s+(\d+)", raw)
        if m:
            info.os_name = f"Windows {m.group(1)}"
            if not info.os_version:
                info.os_version = f"10.0.{m.group(2)}"
                info.os_build = m.group(2)

    # If still no name, try CDB banner: "Windows Debugger Version 10.0.22621"
    if not info.os_name or "Debugger" in info.os_name:
        m = re.search(r"Windows\s+(\d+)\s+Version\s+(\d+)", raw)
        if m:
            info.os_name = f"Windows {m.group(1)}"
            if not info.os_version:
                info.os_version = f"10.0.{m.group(2)}"
                info.os_build = m.group(2)

    # Source 4: OSPLATFORM_TYPE: x64
    m = re.search(r"OSPLATFORM_TYPE:\s*(x86|x64|ARM64|AArch64)", raw)
    if m:
        info.platform = m.group(1)
    else:
        m = re.search(r"(x86|x64|ARM64|AArch64)\s+(\w+)", raw)
        if m:
            info.platform = m.group(1)

    # System Uptime
    m = re.search(r"System Uptime:\s*(\d+)\s*days?\s*(\d+):(\d+):(\d+)", raw)
    if m:
        days = int(m.group(1))
        info.system_uptime_seconds = (
            days * 86400
            + int(m.group(2)) * 3600
            + int(m.group(3)) * 60
            + int(m.group(4))
        )

    # Boot time
    m = re.search(r"Boot Time [\d.]+\s+([\d/]+\s+[\d:]+)", raw)
    if m:
        info.boot_time = m.group(1).strip()

    # Machine name (from vertarget: "Machine Name:" or from !envvar: COMPUTERNAME=)
    m = re.search(r"Machine\s*Name:\s*(\S+)", raw, re.IGNORECASE)
    if m and m.group(1) and m.group(1) not in ("Debug", "Not"):
        info.machine_name = m.group(1)
    if not info.machine_name:
        m = re.search(r"COMPUTERNAME=(\S+)", raw)
        if m:
            info.machine_name = m.group(1)

    # --- !cpuinfo: CPU model and features ---
    # Look for CPU vendor/model lines
    m = re.search(r"(?:Processor|CPU)\s*:\s*(.+?)(?:\n|$)", raw)
    if m:
        info.cpu_model = m.group(1).strip()[:200]

    # CPU count from multiple sources (most specific first)
    cpu_count = 0
    # "CPUs: 20" in !cpuinfo
    m = re.search(r"CPUs:\s*(\d+)", raw)
    if m:
        cpu_count = int(m.group(1))
    # "N processors" on its own line (from !cpuinfo)
    if cpu_count == 0:
        m = re.search(r"^(\d+)\s+processors?\s*$", raw, re.IGNORECASE | re.MULTILINE)
        if m:
            cpu_count = int(m.group(1))
    # "MP (N procs)" in vertarget — least reliable source
    if cpu_count == 0:
        m = re.search(r"MP\s*\((\d+)\s*procs?\)", raw)
        if m:
            cpu_count = int(m.group(1))
    # Thread count from ~* k output as fallback
    if cpu_count == 0:
        cpu_count = len(re.findall(r"^\s*(\d+)\s+Id:", raw, re.MULTILINE))
    info.cpu_count = cpu_count or 1

    # CPU features (SSE, AVX, etc.)
    features = set()
    for feat in ["SSE2", "SSE3", "SSSE3", "SSE4.1", "SSE4.2",
                 "AVX", "AVX2", "AVX512", "AVX512F", "AVX512DQ",
                 "FMA3", "F16C", "BMI1", "BMI2", "AES-NI",
                 "SHA", "RDRAND", "RDSEED", "ADX", "MOVBE",
                 "NEON", "SVE"]:
        if re.search(rf"\b{feat}\b", raw):
            features.add(feat)
    info.cpu_features = sorted(features)

    # --- !vm: virtual memory statistics ---
    # PageFile:  xxx ( xxx Mb )
    m = re.search(r"PageFile:\s*\S+\s*\(\s*(\d+)\s*Mb\s*\)", raw)
    if m:
        info.total_pagefile_mb = int(m.group(1))

    # Physical:  xxxxxx ( xxxx Mb )
    m = re.search(r"Physical:\s*\S+\s*\(\s*(\d+)\s*(?:Mb)?\s*\)", raw)
    if m:
        info.total_physical_mb = int(m.group(1))

    # Available: xxxxxx ( xxxx Mb )
    m = re.search(r"Avail(?:able)?:\s*\S+\s*\(\s*(\d+)\s*(?:Mb)?\s*\)", raw)
    if m:
        info.available_physical_mb = int(m.group(1))

    # --- !memusage: process memory ---
    m = re.search(r"(?:WorkingSet|Working set|WS)\s*:\s*\S+\s*\(\s*(\d+)\s*(?:Mb|KB)", raw)
    if m:
        val = int(m.group(1))
        info.process_working_set_mb = val if "Mb" in m.group(0) else val // 1024

    # --- !envvar: environment variables ---
    env_vars = {}
    for match in re.finditer(r"^([A-Z_][A-Z0-9_]*)=(.*?)$", raw, re.MULTILINE):
        key = match.group(1)
        # Filter out common but useless vars, keep potentially meaningful ones
        if key in ("PATH", "PATHEXT", "PSModulePath", "SystemRoot", "windir",
                    "USERNAME", "USERDOMAIN", "USERPROFILE", "TEMP", "TMP",
                    "ALLUSERSPROFILE", "CommonProgramFiles", "ComSpec",
                    "ProgramData", "ProgramFiles", "ProgramW6432",
                    "PROCESSOR_ARCHITECTURE", "PROCESSOR_IDENTIFIER",
                    "PROCESSOR_LEVEL", "PROCESSOR_REVISION",
                    "NUMBER_OF_PROCESSORS", "LOGONSERVER",
                    "SESSIONNAME", "CLIENTNAME", "AppData",
                    "COMPUTERNAME", "HOMEDRIVE", "HOMEPATH"):
            continue
        env_vars[key] = match.group(2)
    info.environment = env_vars

    return info


# ---------------------------------------------------------------------------
# Exception info
# ---------------------------------------------------------------------------

_EXCEPTION_CODES = {
    "C0000005": "ACCESS_VIOLATION",
    "C000000D": "STATUS_INVALID_PARAMETER",
    "C0000017": "STATUS_NO_MEMORY",
    "C0000022": "STATUS_ACCESS_DENIED",
    "C0000023": "STATUS_BUFFER_TOO_SMALL",
    "C0000024": "STATUS_OBJECT_NAME_INVALID",
    "C0000034": "STATUS_OBJECT_NAME_NOT_FOUND",
    "C0000039": "STATUS_OBJECT_PATH_INVALID",
    "C00000FD": "STACK_OVERFLOW",
    "C000008C": "ARRAY_BOUNDS_EXCEEDED",
    "C000008D": "FLOAT_DENORMAL_OPERAND",
    "C000008E": "FLOAT_DIVIDE_BY_ZERO",
    "C000008F": "FLOAT_INEXACT_RESULT",
    "C0000090": "FLOAT_INVALID_OPERATION",
    "C0000091": "FLOAT_OVERFLOW",
    "C0000092": "FLOAT_STACK_CHECK",
    "C0000093": "FLOAT_UNDERFLOW",
    "C0000094": "INTEGER_DIVIDE_BY_ZERO",
    "C0000095": "INTEGER_OVERFLOW",
    "C0000096": "PRIVILEGED_INSTRUCTION",
    "C00000B8": "STATUS_ILLEGAL_INSTRUCTION",
    "C0000135": "DLL_NOT_FOUND",
    "C0000139": "ENTRYPOINT_NOT_FOUND",
    "C0000142": "DLL_INIT_FAILED",
    "C000021A": "STATUS_SYSTEM_PROCESS_TERMINATED",
    "C0000221": "STATUS_IMAGE_CHECKSUM_MISMATCH",
    "C000026E": "STATUS_DLL_INIT_FAILED_LOGOFF",
    "C0000374": "HEAP_CORRUPTION",
    "C0000409": "STACK_BUFFER_OVERRUN",
    "C0000417": "INVALID_CRUNTIME_PARAMETER",
    "C0000420": "ASSERTION_FAILURE",
    "C0000602": "STATUS_FAIL_FAST_EXCEPTION",
    "C06D007E": "CPP_EXCEPTION_UNKNOWN",
    "C06D007F": "CPP_EXCEPTION_UNWIND",
    "E06D7363": "CPP_EXCEPTION",
    "E0434352": "CLR_EXCEPTION",
    "E0434F4D": "CLR_EXCEPTION_COM",
    "80000001": "NOT_IMPLEMENTED",
    "80000003": "BREAKPOINT",
    "80000004": "SINGLE_STEP",
    "8000FFFF": "CATASTROPHIC_FAILURE",
    "80131506": "CORRUPT_STATE_EXCEPTION",
}


def parse_exception_info(raw: str) -> ExceptionInfo:
    """Parse exception information from CDB output."""
    info = ExceptionInfo()

    # Strategy 1: Look for "ExceptionCode: c0000409 (description)" in EXCEPTION_RECORD
    m = re.search(
        r"ExceptionCode:\s*([0-9A-Fa-f]{8,})\s*(?:\(([^)]+)\))?",
        raw
    )
    if not m:
        # Strategy 2: Look in the CDB preamble before !analyze -v
        #   "Security check failure or stack buffer overrun - code c0000409"
        m = re.search(
            r"code\s+([0-9A-Fa-f]{8,})",
            raw
        )
    if not m:
        # Strategy 3: EXCEPTION_CODE_STR field
        m = re.search(r"EXCEPTION_CODE_STR:\s*([0-9A-Fa-f]{4,})", raw)

    if m:
        code = m.group(1).upper()
        info.code = code
        # Always prefer the code mapping for consistency, e.g.
        # "C0000005" => "ACCESS_VIOLATION", not "Access violation"
        info.name = _EXCEPTION_CODES.get(code, "")
        # Fall back to the description text if no mapping exists
        if not info.name and len(m.groups()) >= 2 and m.group(2):
            info.name = m.group(2).strip()

    # ExceptionAddress
    m = re.search(r"ExceptionAddress:\s*([0-9A-Fa-f`]+)", raw)
    if m:
        info.address = m.group(1).replace("`", "")
    elif not info.address:
        # FAULTING_IP
        m = re.search(r"FAULTING_IP:\s*\n?\S+\!?\S+\+([0-9A-Fa-f]+)\s*\n?\s*([0-9A-Fa-f`]+)", raw)
        if m:
            info.address = m.group(2).replace("`", "")

    # Attempted read/write/execute address
    # Patterns:
    #   "Attempt to write to address 00000000"
    #   "Attempt to read from address 0000000000000000"
    #   "attempted read at address 0000000000000000"
    m = re.search(
        r"(?:attempt(?:ed)?\s+to\s+)?(read|write|execute)"
        r"(?:.*?(?:from|at|to)\s+address\s+([0-9A-Fa-f`]+))?",
        raw, re.IGNORECASE
    )
    if m:
        info.type = m.group(1).lower()
        if m.group(2):
            info.attempted_address = m.group(2).replace("`", "")
    # ACCESS_VIOLATION Parameter[0]: 0=read, 1=write, 8=execute
    # Parameter[1] is the accessed address
    if not info.type or not info.attempted_address:
        p0 = re.search(r"Parameter\[0\]:\s+([0-9A-Fa-f`]+)", raw)
        p1 = re.search(r"Parameter\[1\]:\s+([0-9A-Fa-f`]+)", raw)
        if p0:
            p0v = int(p0.group(1).replace("`", ""), 16)
            info.type = {0: "read", 1: "write", 8: "execute"}.get(p0v, "")
        if p1:
            info.attempted_address = p1.group(1).replace("`", "")

    # First chance / second chance
    if "second chance" in raw.lower():
        info.first_chance = False

    # In-page error
    if re.search(r"in.page.*error", raw, re.IGNORECASE):
        info.in_page_error = True

    # Security violation: CFG, stack buffer overrun, etc.
    if re.search(
        r"(security check failure|stack buffer overrun|control flow guard|"
        r"cfg guard|fast_fail_fatal)",
        raw, re.IGNORECASE
    ):
        info.security_violation = True

    return info


# ---------------------------------------------------------------------------
# Callstack parsing
# ---------------------------------------------------------------------------

_CALLSTACK_FRAME_RE = re.compile(
    r"""
    ^\s*                    # leading whitespace
    (?:[0-9A-Fa-f`]+\s+)?   # optional address
    ([0-9A-Fa-f`]+)\s+      # return address / frame address
    (\S+?)                   # module!function+offset
    \s*
    (?:\[[^\]]*\]:\s*(\d+)\s+)?   # optional [file]: line
    (?:.*?)                  # rest
    $
    """,
    re.VERBOSE
)

_SIMPLE_FRAME_RE = re.compile(
    r"([0-9A-Fa-f`]+)\s+(\S+?\!?\S+\+0x[0-9A-Fa-f]+)\s*(?:\[[^\]]*\]:\s*(\d+))?"
)


def parse_callstack(text_block: str) -> list[Frame]:
    """Parse a callstack text block into a list of Frame objects."""
    frames = []
    lines = text_block.strip().split("\n")

    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        # Skip header lines
        if "Child-SP" in line or "RetAddr" in line or "Call Site" in line:
            continue
        if line.startswith("#") and "Child" in line:
            continue

        # Strategy 1: Numbered frame — "00 address address module!func+0x42"
        # Also handles: "00 (Inline) address module!func+0x5"
        m = re.match(
            r"^([0-9a-fA-F]{2})\s+"           # frame number "00".."FF" (always 2 hex digits)
            r"(?:\(Inline\)\s+)?"              # optional inline marker — skip it
            r"(?:[0-9A-Fa-f`]+\s+)?"           # optional first address (may be absent for inline)
            r"([0-9A-Fa-f`]+)\s+"              # address (RetAddr or Child-SP)
            r"(\S+)"                            # module!function+offset
            r"(?:\s+.*?)?$",                   # optional rest
            line
        )
        if m:
            frame = Frame(
                frame_index=int(m.group(1), 16),
                function=m.group(3),
                offset="",
            )
            if "!" in frame.function:
                frame.module = frame.function.split("!")[0]
            src = re.search(r"\[([^\]]+)\s+[@:]\s+(\d+)\]", line)
            if src:
                frame.source_file = src.group(1)
                frame.source_line = int(src.group(2))
            frames.append(frame)
            continue

        # Strategy 2: ChildEBP RetAddr format from ".ecxr; k":
        #   001df988 004c1a6e     CrashDumpDemo!TriggerTestCrash+0x1f [path @ 89]
        m = re.match(
            r"^([0-9A-Fa-f`]+)\s+([0-9A-Fa-f`]+)\s+(\S+)"
            r"(?:\s+\[([^\]]+)\s+[@:]\s+(\d+)\])?",
            line
        )
        if m and "!" in m.group(3):
            frame = Frame(
                frame_index=len(frames),
                module=m.group(3).split("!")[0],
                function=m.group(3),
                offset="",
                source_file=m.group(4) if m.lastindex and m.lastindex >= 4 else None,
                source_line=int(m.group(5)) if m.lastindex and m.lastindex >= 5 and m.group(5) else None,
            )
            frames.append(frame)
            continue

        # Strategy 3: Fallback — just function name on a line
        m = re.match(r"^(\S+)$", line)
        if m and "!" in m.group(1):
            frames.append(Frame(
                frame_index=len(frames),
                function=m.group(1),
                module=m.group(1).split("!")[0],
            ))

    return frames


def parse_all_threads(raw: str) -> list[ThreadStack]:
    """Parse all thread callstacks from CDB output.

    CDB outputs threads in format:
        <thread_id> Id: <id>.<sub> <state>
        <callstack lines>
    """
    threads = []
    # Split by thread header pattern
    thread_blocks = re.split(
        r"\n(?=\s*\d+\s+Id:\s*[0-9A-Fa-f]+)", raw
    )
    # Also try the ~* k output format
    if len(thread_blocks) == 1:
        thread_blocks = re.split(r"\n(?=\s*\d+\s+)", raw)

    for block in thread_blocks:
        block = block.strip()
        if not block:
            continue

        # Extract thread ID and state
        # Format: "0  Id: process.thread" — thread ID is after the dot
        m = re.search(r"(\d+)\s+Id:\s*([0-9A-Fa-f]+)\.([0-9A-Fa-f]+)", block)
        if m:
            tid = int(m.group(3), 16)  # thread ID is after the dot
        else:
            m = re.search(r"(\d+)\s+Id:\s*([0-9A-Fa-f]+)", block)
            tid = int(m.group(2), 16) if m else 0

        state = "running"
        if "Suspended" in block:
            state = "suspended"
        elif "Wait" in block or "waiting" in block.lower():
            state = "waiting"

        # Check if this is the crashed thread
        if "Crashed" in block or "crashed" in block.lower():
            state = "crashed"

        frames = parse_callstack(block)
        if frames or tid:
            threads.append(ThreadStack(
                thread_id=tid,
                state=state,
                callstack=frames,
            ))

    return threads


# ---------------------------------------------------------------------------
# Module list
# ---------------------------------------------------------------------------

def parse_module_list(raw: str) -> list[ModuleInfo]:
    """Parse ``lm`` or ``lm vm`` output into ModuleInfo list.

    Handles both compact ``lm`` format::

        004c0000 004d7000   CrashDumpDemo C (private pdb symbols)  d:\\...\\CrashDumpDemo.pdb
        75990000 75a80000   kernel32   (export symbols)       kernel32.dll
        007a0000 007c4000   klhkum_...   (deferred)

    And verbose ``lm vm`` format with indented detail blocks.
    """
    modules = []

    # Pattern for compact "lm" output lines:
    #   start_addr end_addr   name  [C] [(status)]  [optional_path]
    _LM_LINE = re.compile(
        r"^([0-9A-Fa-f`]+)\s+([0-9A-Fa-f`]+)\s+(\S+)\s*"
        r"(?:C\s+)?(?:\((.+?)\)\s*)?(\S*)$",
        re.MULTILINE
    )

    # Known false positives from CDB disassembly in output
    _NOT_MODULES = {"ret", "call", "jmp", "nop", "int3", "push", "pop",
                    "mov", "add", "sub", "cmp", "test", "xor", "lea",
                    "cdb:", "quit:", "natvis"}

    for m in _LM_LINE.finditer(raw):
        base = m.group(1).replace("`", "")
        end_addr = m.group(2).replace("`", "")
        name = m.group(3)
        # Skip false positives
        if name.lower() in _NOT_MODULES or len(name) < 2:
            continue
        status = (m.group(4) or "").strip()
        extra_path = (m.group(5) or "").strip()

        try:
            size = max(0, int(end_addr, 16) - int(base, 16))
        except ValueError:
            size = 0

        mod = ModuleInfo(name=name, base_address=base, size=size)

        # Symbol status
        mod.has_symbols = "pdb" in status.lower() or "symbols" in status.lower()

        # Path from the extra column
        if extra_path and not extra_path.startswith("("):
            mod.path = extra_path

        modules.append(mod)

    # Try the verbose "lm vm" format first (more detail), fall back to
    # compact "lm" format only if verbose produces nothing.
    modules_from_compact = modules
    modules = []

    # Try "lm vm" verbose format (status marker optional)
    # Uses [^\S\n]* (horizontal space only) to avoid consuming the
    # newline before indented detail lines. Lookahead handles
    # optional blank line between modules.
    for match in re.finditer(
        r"([0-9A-Fa-f`]+)\s+([0-9A-Fa-f`]+)\s+(\S+)[^\S\n]*"
        r"(?:\((?:deferred|pdb symbols|export symbols|private pdb symbols)\)[^\S\n]*)?"
        r"((?:\n\s{4,}.+?)*?)(?=\n\s*\n[0-9A-Fa-f`]+\s+[0-9A-Fa-f`]+\s+\S|\n\Z|\Z)",
        raw
    ):
        base = match.group(1).replace("`", "")
        end_addr = match.group(2).replace("`", "")
        name = match.group(3)
        detail_block = match.group(4) if match.lastindex and match.lastindex >= 4 else ""

        try:
            size = max(0, int(end_addr, 16) - int(base, 16))
        except ValueError:
            size = 0

        mod = ModuleInfo(name=name, base_address=base, size=size)

        fp = re.search(r"(?:Image path|Mapped memory image file):\s*(.+)", detail_block)
        if fp:
            mod.path = fp.group(1).strip()

        ver = re.search(r"File version:\s*(\S+)", detail_block)
        if ver:
            mod.version = ver.group(1)

        ts = re.search(r"Timestamp:\s*(.+)", detail_block)
        if ts:
            mod.timestamp = ts.group(1).strip()

        mod.has_symbols = (
            "pdb symbols" in detail_block.lower()
            or "symbols loaded" in detail_block.lower()
        )

        modules.append(mod)

    if modules:
        return modules

    # If verbose format found nothing, use compact format results
    return modules_from_compact


# ---------------------------------------------------------------------------
# Heap info
# ---------------------------------------------------------------------------

def parse_heap_info(raw: str) -> HeapInfo:
    """Parse !heap -s output — handles both verbose and empty results.

    Extracts: heap_count, committed/reserved/free bytes, segment count,
    LFH status, per-heap breakdown, and corruption indicators.
    Falls back gracefully when !heap -s returns empty.
    """
    info = HeapInfo()

    m = re.search(r"(\d+)\s+heaps", raw)
    if m:
        info.heap_count = int(m.group(1))

    # LFH enabled check — must have a non-zero key
    if re.search(r"LFH\s+Key:\s*0x[0-9a-f]*[1-9a-f]", raw, re.IGNORECASE):
        info.lfh_enabled = True

    # Per-heap parsing: find each heap block
    heap_blocks = re.split(r"\n\s*(?=Heap\s+)", raw)
    total_committed = 0
    total_reserved = 0
    total_free = 0
    total_segments = 0

    for block in heap_blocks:
        if not block.strip():
            continue

        heap_addr = ""
        addr_m = re.search(r"Heap\s+([0-9a-f`]+)", block, re.IGNORECASE)
        if addr_m:
            heap_addr = addr_m.group(1).replace("`", "")

        commit_mb = 0
        reserve_mb = 0
        free_bytes = 0
        segments = 0

        # Committed
        for cm in re.finditer(r"(?:[Cc]ommit(?:ted)?)\s+.*?(\d+)\s*(?:Mb|MB|kb|KB)", block):
            val = int(cm.group(1))
            if "kb" in cm.group(0).lower():
                val //= 1024
            commit_mb += val
            total_committed += val

        # Reserved
        for rm in re.finditer(r"(?:[Rr]eserv(?:ed)?)\s+.*?(\d+)\s*(?:Mb|MB|kb|KB)", block):
            val = int(rm.group(1))
            if "kb" in rm.group(0).lower():
                val //= 1024
            reserve_mb += val
            total_reserved += val

        # Free
        for fm in re.finditer(r"(?:[Ff]ree)\s+.*?(\d+)\s*(?:bytes|KB|kb|MB|Mb)", block):
            val = int(fm.group(1))
            unit = fm.group(0).lower()
            if "kb" in unit:
                val *= 1024
            elif "mb" in unit:
                val *= 1024 * 1024
            free_bytes += val
            total_free += val

        # Segments
        seg_m = re.search(r"(?:Virtual address space|segments?)[:\s]+(\d+)\s*segments?", block, re.IGNORECASE)
        if not seg_m:
            seg_m = re.search(r"(\d+)\s*segments?", block, re.IGNORECASE)
        if seg_m:
            segments = int(seg_m.group(1))
            total_segments += segments

        if heap_addr:
            info.per_heap_breakdown.append({
                "address": heap_addr,
                "commit_mb": commit_mb,
                "reserve_mb": reserve_mb,
                "free_bytes": free_bytes,
                "segments": segments,
            })

    info.total_committed_mb = total_committed
    info.total_reserved_mb = total_reserved
    info.free_bytes = total_free
    info.segment_count = total_segments

    # Corrupted? Check for actual corruption indicators, not the
    # "Termination on corruption: ENABLED" WER setting.
    if re.search(
        r"(?:heap.*(?:corrupt|damage|error)|"
        r"corruption\s+detected|"
        r"HEAP_CORRUPTION|"
        r"block.*modified.*after.*freed|"
        r"use.after.free)",
        raw, re.IGNORECASE
    ):
        info.corrupted = True
        for line in raw.split("\n"):
            if re.search(r"(corrupt|error|invalid|damage|modified|after.*freed)",
                         line, re.IGNORECASE) and \
               "termination on corruption" not in line.lower():
                info.details.append(line.strip()[:200])

    return info


def parse_address_summary(raw: str) -> dict:
    """Parse !address -summary output.

    Extracts per-category virtual address usage (Free, Image, Heap, Stack,
    MappedFile, TEB, PEB, etc.) and the largest free block.

    This is a critical fallback when !heap -s returns empty — address
    summary always works regardless of heap state.

    Returns:
        dict with keys like "Free", "Image", "Heap", "Stack", "MappedFile",
        "LargestFreeBlock" — all values in MB (int).
    """
    result: dict[str, int] = {}

    # Parse Usage Summary table: category name and size
    # Lines like: "Free     45    7ffe`00000000 ( 127.992 TB)    65.00%"
    for m in re.finditer(
        r"(\w+)\s+\d+\s+[0-9a-f`]+\s*\(([^)]+)\)",
        raw, re.IGNORECASE,
    ):
        category = m.group(1).strip()
        size_str = m.group(2).strip()
        result[category] = _parse_size_to_mb(size_str)

    # Largest free block
    lfb = re.search(
        r"Largest\s*(?:free)?\s*block[:\s]+[0-9a-f`]+\s*\(([^)]+)\)",
        raw, re.IGNORECASE,
    )
    if lfb:
        result["LargestFreeBlock"] = _parse_size_to_mb(lfb.group(1).strip())

    return result


def _parse_size_to_mb(size_str: str) -> int:
    """Convert a size string like '127.992 TB' or '650.000 MB' to MB (int)."""
    size_str = size_str.strip().upper().replace(",", ".")
    # Extract numeric value and unit
    m = re.match(r"([\d.]+)\s*(TB|GB|MB|KB|BYTES?)", size_str)
    if not m:
        return 0
    value = float(m.group(1))
    unit = m.group(2)
    if unit == "TB":
        value *= 1024 * 1024
    elif unit == "GB":
        value *= 1024
    elif unit == "KB" or unit == "BYTES" or unit == "BYTE":
        value /= 1024
    return int(value)


# ---------------------------------------------------------------------------
# Lock info
# ---------------------------------------------------------------------------

def parse_locks(raw: str) -> list[LockInfo]:
    """Parse !locks output."""
    locks = []

    for line in raw.split("\n"):
        # Critical section lines look like:
        # CritSec ntdll!LdrpLoaderLock+0 at 00007fff`12345678
        # LockCount 1, WaiterCount 0
        m = re.search(
            r"(\S+?)\s+at\s+([0-9A-Fa-f`]+)",
            line
        )
        if m:
            lock = LockInfo(
                lock_type="critical_section",
                address=m.group(2).replace("`", ""),
            )
            locks.append(lock)

    return locks


# ---------------------------------------------------------------------------
# Top-level parser
# ---------------------------------------------------------------------------

def parse_cdb_output(raw: str, dump_path: str) -> DmpData:
    """Parse complete CDB output into a DmpData struct.

    This is the main entry point. It splits the CDB output into
    meaningful sections and delegates to the specific parsers.
    """
    data = DmpData()

    # Metadata
    data.metadata = DmpMetadata(
        dump_type=_detect_dump_type(raw, dump_path),
        timestamp=_extract_crash_time(raw),
    )

    # System info
    data.system_info = parse_system_info(raw)

    # Exception
    data.exception = parse_exception_info(raw)

    # Crash callstack — try to find the crashing thread's stack
    data.crash_callstack = _extract_crash_callstack(raw)

    # All threads
    data.all_callstacks = parse_all_threads(raw)

    # Modules
    data.modules = parse_module_list(raw)

    # Heap
    data.heap = parse_heap_info(raw)

    # Locks
    data.locks = parse_locks(raw)

    # Registers (simple extraction from !analyze -v)
    data.registers = _extract_registers(raw)

    # Keep raw output for debugging / richer AI analysis
    data.raw_analyze_output = raw

    return data


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _detect_dump_type(raw: str, dump_path: str) -> str:
    """Detect dump type from filename or content."""
    path_lower = dump_path.lower()
    if "full" in path_lower:
        return "full"
    if "kernel" in path_lower:
        return "kernel"
    if "mini" in path_lower:
        return "minidump"
    if re.search(r"(MiniDump|User Mini Dump)", raw):
        return "minidump"
    if re.search(r"(Full Dump|User Dump)", raw):
        return "full"
    if re.search(r"(Kernel|Kernel Dump)", raw):
        return "kernel"
    return "minidump"  # default assumption


def _extract_crash_time(raw: str) -> str:
    """Extract crash timestamp from CDB output."""
    # .time output: "Debug session time: Tue Jun 23 15:26:44.000 2026 (UTC + 8:00)"
    m = re.search(
        r"Debug session time:\s*(.+)",
        raw
    )
    if m:
        return m.group(1).strip()
    # Also try "Crash Time:" (kernel dumps)
    m = re.search(
        r"Crash Time:\s*(.+)",
        raw
    )
    if m:
        return m.group(1).strip()
    # Try to find a timestamp in the output
    m = re.search(r"(\d{4}[-/]\d{2}[-/]\d{2}\s+\d{2}:\d{2}:\d{2})", raw)
    if m:
        return m.group(1)
    return datetime.now().isoformat()


def _extract_crash_callstack(raw: str) -> list[Frame]:
    """Extract the crash thread's callstack.

    Priority order:
    1. ChildEBP RetAddr from .ecxr; k  → full symbols from local PDB
    2. STACK_TEXT from !analyze -v     → may have WRONG_SYMBOLS
    3. LAST_CONTROL_TRANSFER           → fallback
    4. Any block of 3+ hex frame lines → heuristic
    """
    stack_section = ""

    # Strategy 1: ChildEBP RetAddr from ".ecxr; k" — BEST: has resolved
    # symbols from the EXE dir PDB, including source file/line.
    m = re.search(
        r"ChildEBP\s+RetAddr\s*\n(.*?)(?=\n\n[^\s]|\nstart\s+end|\n\s*\n[A-Z_]{3}|\Z)",
        raw, re.DOTALL
    )
    if m:
        stack_section = m.group(1)

    if not stack_section:
        # Strategy 2: STACK_TEXT from !analyze -v
        m = re.search(
            r"STACK_TEXT:\s*\n(.*?)(?=\n\s*\n[A-Z_]|\nSTACK_COMMAND|\Z)",
            raw, re.DOTALL
        )
        if m:
            stack_section = m.group(1)

    if not stack_section:
        # Strategy 3: LAST_CONTROL_TRANSFER
        m = re.search(
            r"LAST_CONTROL_TRANSFER:\s*\n(.*?)(?:\n\n|\Z)",
            raw, re.DOTALL
        )
        if m:
            stack_section = m.group(1)

    if not stack_section:
        # Strategy 4: Any block of 3+ hex frame lines (heuristic)
        m = re.search(
            r"((?:(?:[0-9a-fA-F]{2})\s+[0-9A-Fa-f`]+\s+[0-9A-Fa-f`]+\s+\S+.*?\n){3,})",
            raw
        )
        if m:
            stack_section = m.group(1)

    # Parse the frames using the shared parser
    if stack_section:
        return parse_callstack(stack_section)

    return []


def _extract_registers(raw: str) -> dict[str, str]:
    """Extract register values from CDB output.

    Looks for the CONTEXT: (.ecxr) section which contains register dump
    in the format: rax=... rbx=... (may span multiple lines).
    """
    regs = {}

    # Find the CONTEXT block: from "CONTEXT:" to "Resetting default scope"
    ctx_match = re.search(
        r"CONTEXT:.*?\.ecxr\)\s*\n(.*?)(?:Resetting default scope|\n\n)",
        raw, re.DOTALL
    )
    ctx_text = ctx_match.group(1) if ctx_match else raw

    # Normalize: join continuation lines, handle ` in addresses
    # Lines look like:
    #   rax=000000325717c530 rbx=000000325717cab0 rcx=000000325717c530
    #   rdx=000000325717c9e0 rsi=000000325717cab0 rdi=000000325717c530
    ctx_text = ctx_text.replace("`", "")

    for reg in ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                "rip", "efl", "cs", "ss", "ds", "es", "fs", "gs",
                "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
                "xmm0", "xmm1", "xmm2", "xmm3"]:
        m = re.search(rf"{reg}=([0-9A-Fa-f]+)", ctx_text)
        if m:
            regs[reg] = m.group(1)

    return regs
