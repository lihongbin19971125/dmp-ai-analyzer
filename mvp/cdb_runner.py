"""CDB (Console Debugger) invocation wrapper.

Handles finding CDB.exe and running debugger command sequences
against a dump file, capturing all output.
"""

import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional


# Known installation paths for Windows SDK debuggers
_CDB_SEARCH_PATHS = [
    # Windows 11 SDK / Windows 10 SDK (64-bit preferred)
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\10\Debuggers\arm64\cdb.exe",
    # Older SDK paths
    r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\8.1\Debuggers\x86\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x64\cdb.exe",
    r"C:\Program Files (x86)\Windows Kits\8.0\Debuggers\x86\cdb.exe",
    # Debugging Tools for Windows (legacy)
    r"C:\Debuggers\x64\cdb.exe",
    r"C:\Debuggers\x86\cdb.exe",
    # WinDbg Preview
    r"C:\Program Files\WindowsApps\Microsoft.WinDbg_*\amd64\cdb.exe",
]


def find_cdb(explicit_path: Optional[str] = None) -> str:
    """Locate the CDB debugger executable.

    Search order:
    1. Explicit path if provided
    2. CDB_PATH / CDB environment variables
    3. Known SDK install locations
    4. PATH

    Returns:
        Absolute path to cdb.exe.

    Raises:
        FileNotFoundError: If CDB cannot be found.
    """
    if explicit_path:
        p = Path(explicit_path)
        if p.is_file():
            return str(p.resolve())
        raise FileNotFoundError(f"CDB not found at explicit path: {explicit_path}")

    # Check environment variables
    for var in ("CDB_PATH", "CDB"):
        val = os.environ.get(var)
        if val and Path(val).is_file():
            return str(Path(val).resolve())

    # Check known install locations
    for pattern in _CDB_SEARCH_PATHS:
        # Handle wildcards in paths
        import glob as _glob
        matches = _glob.glob(pattern)
        for match in matches:
            if Path(match).is_file():
                return str(Path(match).resolve())

    # Fall back to PATH
    import shutil
    found = shutil.which("cdb.exe") or shutil.which("cdb")
    if found:
        return found

    raise FileNotFoundError(
        "Cannot find CDB.exe. Please install the Windows SDK Debugging Tools "
        "or set the CDB_PATH environment variable to the full path of cdb.exe.\n"
        "Download: https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/"
    )


def build_command_script(commands: list[str]) -> str:
    """Build a CDB command script string.

    CDB uses a specific script format. Commands are separated by
    semicolons or newlines. The script should end with 'q' to quit.

    NOTE: This function is kept for backward compatibility and testing.
    The `run_cdb` function now uses inline commands via `-c` flag.

    Args:
        commands: List of debugger commands to execute.

    Returns:
        Script text ready to write to a temp file.
    """
    # Join with semicolons, add quit at the end if not already present
    script = "; ".join(commands)
    stripped = script.rstrip().rstrip(";")
    if not stripped.endswith("; q") and not stripped.endswith(";q"):
        script = stripped + "; q"
    else:
        script = stripped
    return script


def run_cdb(
    dump_path: str,
    commands: list[str],
    cdb_path: Optional[str] = None,
    timeout: int = 120,
    symbol_path: Optional[str] = None,
) -> str:
    """Run CDB against a dump file and capture all output.

    Args:
        dump_path: Path to the .dmp file.
        commands: List of debugger commands (e.g. ["!analyze -v", "k 50"]).
        cdb_path: Optional explicit path to cdb.exe.
        timeout: Maximum time in seconds for CDB to run.
        symbol_path: Optional semicolon-separated symbol paths.

    Returns:
        Combined stdout + stderr output from CDB.

    Raises:
        FileNotFoundError: If CDB or the dump file is not found.
        subprocess.TimeoutExpired: If CDB takes longer than `timeout`.
    """
    dump = Path(dump_path).resolve()
    if not dump.is_file():
        raise FileNotFoundError(f"Dump file not found: {dump_path}")

    cdb = find_cdb(cdb_path)

    # Build the command string — use inline semicolon-separated commands.
    # This avoids issues with $<script_file syntax and temp file encoding.
    cmd_string = "; ".join(commands)
    if not cmd_string.rstrip().endswith("; q"):
        cmd_string += "; q"

    # Build environment
    env = os.environ.copy()
    if symbol_path is not None:
        env["_NT_SYMBOL_PATH"] = symbol_path
    elif "_NT_SYMBOL_PATH" not in os.environ:
        # Default: NO symbol server to avoid network hangs.
        env["_NT_SYMBOL_PATH"] = ""

    # CDB command line
    cmd = [
        cdb,
        "-z", str(dump),
        "-c", cmd_string,
        "-lines",
        "-noshell",
    ]

    # Use temporary files for stdout/stderr to avoid pipe buffer issues
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as out_f, tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, encoding="utf-8"
    ) as err_f:
        out_path = out_f.name
        err_path = err_f.name

    try:
        subprocess.run(
            cmd,
            stdout=open(out_path, "w", encoding="utf-8"),
            stderr=open(err_path, "w", encoding="utf-8"),
            timeout=timeout,
            env=env,
        )
        with open(out_path, encoding="utf-8", errors="replace") as f:
            output = f.read()
        with open(err_path, encoding="utf-8", errors="replace") as f:
            err_output = f.read()
        if err_output.strip():
            output += "\n[CDB STDERR]\n" + err_output
        return output
    finally:
        for p in (out_path, err_path):
            try:
                os.unlink(p)
            except OSError:
                pass


# ---------------------------------------------------------------------------
# Pre-built command sets
# ---------------------------------------------------------------------------

def commands_for_system_info() -> list[str]:
    """Commands that extract crash-machine system information from the DMP."""
    return [
        "vertarget",
        "!sysinfo smbios",
        "!cpuinfo",
        "!vm",
        "!memusage",
        "!envvar",
        ".time",
    ]


def commands_for_crash_analysis() -> list[str]:
    """Commands for deep crash analysis.

    Note: we do NOT include .symfix or .reload by default because they
    trigger slow symbol downloads from the Microsoft symbol server.
    The symbol path is set via _NT_SYMBOL_PATH environment variable,
    and CDB resolves symbols on-demand.
    """
    return [
        "!analyze -v",
        ".ecxr",
        "k 50",
        "~* k",
        "lm vm",
        "!locks",
        "!heap -s",
        "!address -summary",
    ]


def commands_for_full_analysis() -> list[str]:
    """Combined command set for a complete analysis pass."""
    cmds = commands_for_system_info()
    cmds.extend(commands_for_crash_analysis())
    return cmds
