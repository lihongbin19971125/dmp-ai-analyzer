"""Tests for cdb_runner.py -- CDB debugger invocation wrapper."""

import builtins
import os
import subprocess
import tempfile
from io import StringIO
from pathlib import Path
from unittest import mock

import pytest

from mvp.cdb_runner import (
    find_cdb,
    build_command_script,
    run_cdb,
    commands_for_system_info,
    commands_for_crash_analysis,
    commands_for_full_analysis,
    _CDB_SEARCH_PATHS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _temp_file_path():
    """Create a real temp file and return its absolute path."""
    fd, path = tempfile.mkstemp(suffix=".exe")
    os.close(fd)
    return path


def _remove_temp(path):
    """Safely remove a temp file."""
    try:
        os.unlink(path)
    except OSError:
        pass


def _make_tempfile_mocks(out_name, err_name):
    """Create a pair of MagicMock objects suitable for mocking
    tempfile.NamedTemporaryFile as a context manager.

    Returns (mock_tmpfile, out_path, err_path) where mock_tmpfile is the
    patch target and out_path/err_path are the string names that will be
    resolved when code accesses out_f.name inside the with-block.
    """
    mock_out = mock.MagicMock()
    mock_out.name = out_name
    mock_out.__enter__.return_value = mock_out

    mock_err = mock.MagicMock()
    mock_err.name = err_name
    mock_err.__enter__.return_value = mock_err

    return [mock_out, mock_err], out_name, err_name


# ---------------------------------------------------------------------------
# Tests: find_cdb
# ---------------------------------------------------------------------------

class TestFindCdbExplicitPath:
    """Tests for find_cdb when an explicit path is provided."""

    def test_find_cdb_explicit_path_valid(self):
        """find_cdb with an explicit path that exists returns the resolved path."""
        tmp = _temp_file_path()
        try:
            with mock.patch("glob.glob") as mock_glob, mock.patch(
                "shutil.which"
            ) as mock_which:
                result = find_cdb(explicit_path=tmp)

            assert result == str(Path(tmp).resolve())
            # Must not fall through to glob scan or PATH lookup.
            mock_glob.assert_not_called()
            mock_which.assert_not_called()
        finally:
            _remove_temp(tmp)

    def test_find_cdb_explicit_path_invalid(self):
        """find_cdb raises FileNotFoundError when explicit path does not exist."""
        nonexistent = "C:/nonexistent/path/cdb.exe"
        with pytest.raises(FileNotFoundError, match="CDB not found at explicit path"):
            find_cdb(explicit_path=nonexistent)


class TestFindCdbEnvVar:
    """Tests for find_cdb when reading from environment variables."""

    def test_find_cdb_from_env_var(self):
        """find_cdb reads CDB_PATH env var when no explicit path given."""
        tmp = _temp_file_path()
        try:
            with mock.patch.dict(os.environ, {"CDB_PATH": tmp}, clear=False):
                with mock.patch("glob.glob") as mock_glob, mock.patch(
                    "shutil.which"
                ) as mock_which:
                    result = find_cdb()

            assert result == str(Path(tmp).resolve())
            # Must not fall through to glob scan or PATH lookup.
            mock_glob.assert_not_called()
            mock_which.assert_not_called()
        finally:
            _remove_temp(tmp)

    def test_find_cdb_from_cdb_var(self):
        """find_cdb also respects the CDB (legacy) env var."""
        tmp = _temp_file_path()
        try:
            # Clear CDB_PATH so it falls through to CDB.
            with mock.patch.dict(os.environ, {"CDB": tmp}, clear=True):
                with mock.patch("glob.glob") as mock_glob:
                    result = find_cdb()

            assert result == str(Path(tmp).resolve())
            mock_glob.assert_not_called()
        finally:
            _remove_temp(tmp)


class TestFindCdbNotFound:
    """Tests for find_cdb when CDB cannot be found anywhere."""

    def test_find_cdb_not_found(self):
        """find_cdb raises FileNotFoundError when CDB is nowhere (no SDK, no PATH)."""
        # Clear relevant env vars, mock glob to return nothing, mock which to
        # return None.
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("glob.glob", return_value=[]):
                with mock.patch("shutil.which", return_value=None):
                    with pytest.raises(
                        FileNotFoundError,
                        match="windows-sdk",
                    ):
                        find_cdb()

    def test_find_cdb_glob_matches_but_no_file(self):
        """When glob returns paths that don't actually exist on disk,
        find_cdb falls through to PATH."""
        # Clear env vars, mock glob to return a non-existent path, mock
        # Path.is_file to return False, mock shutil.which to return None.
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("glob.glob", return_value=["C:/fake/cdb.exe"]):
                with mock.patch.object(Path, "is_file", return_value=False):
                    with mock.patch("shutil.which", return_value=None):
                        with pytest.raises(FileNotFoundError, match="windows-sdk"):
                            find_cdb()

    def test_find_cdb_from_path(self):
        """find_cdb falls back to shutil.which on PATH."""
        with mock.patch.dict(os.environ, {}, clear=True):
            with mock.patch("glob.glob", return_value=[]):
                with mock.patch(
                    "shutil.which", side_effect=lambda x: "C:/tools/cdb.exe" if x == "cdb.exe" else None
                ):
                    result = find_cdb()
                assert result == "C:/tools/cdb.exe"


# ---------------------------------------------------------------------------
# Tests: build_command_script
# ---------------------------------------------------------------------------

class TestBuildCommandScript:
    """Tests for build_command_script."""

    def test_build_command_script_basic(self):
        """Build a command script from a simple command list."""
        result = build_command_script(["!analyze -v", "k 50"])
        assert result == "!analyze -v; k 50; q"

    def test_build_command_script_already_ends_with_q(self):
        """Ensure no duplicate '; q' when commands already end with quit."""
        result = build_command_script(["!analyze -v", "k 50", "q"])
        assert result == "!analyze -v; k 50; q"

    def test_build_command_script_semicolon_end_handling(self):
        """Edge case where last command ends with ';q' (marker check)."""
        result = build_command_script(["vertarget", "!analyze -v;q"])
        assert result == "vertarget; !analyze -v;q"

    def test_build_command_script_single_command(self):
        """Single command should also get '; q' appended."""
        result = build_command_script(["!analyze -v"])
        assert result == "!analyze -v; q"

    def test_build_command_script_empty_list(self):
        """Empty command list should produce just '; q'."""
        result = build_command_script([])
        assert result == "; q"


# ---------------------------------------------------------------------------
# Tests: run_cdb
# ---------------------------------------------------------------------------

class TestRunCdbDumpNotFound:
    """Tests for run_cdb when the dump file is missing."""

    def test_run_cdb_dump_not_found(self):
        """run_cdb raises FileNotFoundError when dump file does not exist."""
        nonexistent = "C:/nonexistent/crash.dmp"
        with pytest.raises(FileNotFoundError, match="Dump file not found"):
            run_cdb(dump_path=nonexistent, commands=["!analyze -v"])


class TestRunCdbTimeoutHandling:
    """Tests for run_cdb timeout behaviour."""

    def test_run_cdb_timeout_handling(self):
        """run_cdb propagates subprocess.TimeoutExpired. Temp files are cleaned up."""
        # We need to mock the dump-path check to pass, then mock find_cdb,
        # then mock subprocess.run to raise TimeoutExpired.
        fake_cdb = "C:/fake/cdb.exe"
        fake_dump = "C:/fake/crash.dmp"

        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("mvp.cdb_runner.find_cdb", return_value=fake_cdb):
                with mock.patch("subprocess.run") as mock_run:
                    mock_run.side_effect = subprocess.TimeoutExpired(
                        cmd=[fake_cdb, "-z", fake_dump, "-c", "!analyze -v; q"],
                        timeout=1,
                    )

                    with mock.patch("os.unlink") as mock_unlink:
                        with pytest.raises(subprocess.TimeoutExpired):
                            run_cdb(
                                dump_path=fake_dump,
                                commands=["!analyze -v"],
                                timeout=1,
                            )

                    # Temp files should be cleaned up in finally block.
                    assert mock_unlink.call_count == 2


class TestRunCdbSymbolPath:
    """Tests for run_cdb symbol path handling."""

    @pytest.fixture(autouse=True)
    def _mock_dependencies(self):
        """Common mocks: dump exists, CDB found, subprocess does nothing."""
        self.fake_cdb = "C:/fake/cdb.exe"
        self.fake_dump = "C:/fake/crash.dmp"
        self.mock_run = None
        self._patchers = []

    def _setup_run_mock(self, returncode=0, stdout_content="CDB output", stderr_content=""):
        """Set up mocks for a successful subprocess.run call."""
        # We need to mock:
        #   1. Path.is_file (for dump check and find_cdb)
        #   2. find_cdb
        #   3. subprocess.run
        #   4. builtins.open (to read back temp files)
        #   5. tempfile.NamedTemporaryFile

        self.mock_run = mock.MagicMock(returncode=returncode)

        # Build a custom side_effect for open that returns StringIO with
        # known content depending on the file path.
        _stdout_io = StringIO(stdout_content)
        _stderr_io = StringIO(stderr_content)

        io_map = {}

        def _open_side_effect(path, mode="r", **kwargs):
            # On the write pass: subprocess.run opens files for writing.
            # Return a StringIO so writes are captured (and discarded).
            if "w" in mode:
                return StringIO()
            # On the read pass: return the pre-built StringIO.
            # We track which file we are reading by remembering the write
            # paths from NamedTemporaryFile.
            key = str(path)
            if key in io_map:
                return io_map[key]
            return StringIO("")

        return _open_side_effect, io_map

    def test_run_cdb_with_symbol_path(self):
        """run_cdb passes symbol_path into _NT_SYMBOL_PATH env var for subprocess."""
        sym_path = "srv*C:\\symbols*https://msdl.microsoft.com/download/symbols"

        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("mvp.cdb_runner.find_cdb", return_value=self.fake_cdb):
                with mock.patch("subprocess.run") as mock_run:
                    with mock.patch.object(builtins, "open") as mock_open:
                        with mock.patch(
                            "tempfile.NamedTemporaryFile",
                        ) as mock_tmpfile:
                            # Configure tempfile to return controlled names.
                            out_path = "C:/tmp/stdout.txt"
                            err_path = "C:/tmp/stderr.txt"

                            mock_out = mock.MagicMock()
                            mock_out.name = out_path
                            mock_err = mock.MagicMock()
                            mock_err.name = err_path

                            mock_out.__enter__.return_value = mock_out
                            mock_err.__enter__.return_value = mock_err
                            mock_tmpfile.side_effect = [mock_out, mock_err]

                            # open(): write pass returns a buffer, read pass
                            # returns empty stdout / stderr.
                            stdout_io = StringIO()
                            stderr_io = StringIO()

                            def open_side(path, mode="r", **kw):
                                if "w" in mode:
                                    return StringIO()
                                if str(path) == out_path:
                                    return StringIO(stdout_io.getvalue())
                                if str(path) == err_path:
                                    return StringIO(stderr_io.getvalue())
                                return StringIO("")

                            mock_open.side_effect = open_side

                            run_cdb(
                                dump_path=self.fake_dump,
                                commands=["!analyze -v"],
                                symbol_path=sym_path,
                            )

                    # Verify subprocess.run was called with the correct env.
                    assert mock_run.call_count == 1
                    _, kwargs = mock_run.call_args
                    env_passed = kwargs["env"]
                    assert env_passed["_NT_SYMBOL_PATH"] == sym_path

    def test_run_cdb_default_symbol_path_empty(self):
        """When no symbol_path and no _NT_SYMBOL_PATH in env, default to empty string."""
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("mvp.cdb_runner.find_cdb", return_value=self.fake_cdb):
                with mock.patch("subprocess.run") as mock_run:
                    with mock.patch.object(builtins, "open") as mock_open:
                        with mock.patch(
                            "tempfile.NamedTemporaryFile"
                        ) as mock_tmpfile:
                            out_path = "C:/tmp/stdout.txt"
                            err_path = "C:/tmp/stderr.txt"

                            mock_out = mock.MagicMock()
                            mock_out.name = out_path
                            mock_err = mock.MagicMock()
                            mock_err.name = err_path
                            mock_out.__enter__.return_value = mock_out
                            mock_err.__enter__.return_value = mock_err
                            mock_tmpfile.side_effect = [mock_out, mock_err]

                            def open_side(path, mode="r", **kw):
                                if "w" in mode:
                                    return StringIO()
                                if str(path) == out_path:
                                    return StringIO("")
                                if str(path) == err_path:
                                    return StringIO("")
                                return StringIO("")

                            mock_open.side_effect = open_side

                            # Clear _NT_SYMBOL_PATH from the copied env.
                            with mock.patch.dict(
                                os.environ, {"_NT_SYMBOL_PATH": ""}, clear=False
                            ):
                                # Pop it so the "not in" branch is taken.
                                with mock.patch.object(
                                    os, "environ", new=mock.MagicMock()
                                ) as mock_environ:
                                    # Simulate os.environ.copy() returning a dict
                                    # without _NT_SYMBOL_PATH.
                                    mock_environ.copy.return_value = {}
                                    mock_environ.__contains__ = lambda self, key: False

                                    run_cdb(
                                        dump_path=self.fake_dump,
                                        commands=["!analyze -v"],
                                    )

                    _, kwargs = mock_run.call_args
                    env_passed = kwargs["env"]
                    assert env_passed["_NT_SYMBOL_PATH"] == ""

    def test_run_cdb_respects_existing_symbol_path(self):
        """Pre-existing _NT_SYMBOL_PATH in os.environ is preserved when
        symbol_path not passed."""
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("mvp.cdb_runner.find_cdb", return_value=self.fake_cdb):
                with mock.patch("subprocess.run") as mock_run:
                    with mock.patch.object(builtins, "open") as mock_open:
                        with mock.patch(
                            "tempfile.NamedTemporaryFile"
                        ) as mock_tmpfile:
                            out_path = "C:/tmp/stdout.txt"
                            err_path = "C:/tmp/stderr.txt"

                            mock_out = mock.MagicMock()
                            mock_out.name = out_path
                            mock_err = mock.MagicMock()
                            mock_err.name = err_path
                            mock_out.__enter__.return_value = mock_out
                            mock_err.__enter__.return_value = mock_err
                            mock_tmpfile.side_effect = [mock_out, mock_err]

                            def open_side(path, mode="r", **kw):
                                if "w" in mode:
                                    return StringIO()
                                if str(path) == out_path:
                                    return StringIO("")
                                if str(path) == err_path:
                                    return StringIO("")
                                return StringIO("")

                            mock_open.side_effect = open_side

                            with mock.patch.dict(
                                os.environ, {"_NT_SYMBOL_PATH": "srv*cache"}
                            ):
                                run_cdb(
                                    dump_path=self.fake_dump,
                                    commands=["!analyze -v"],
                                )

                    _, kwargs = mock_run.call_args
                    env_passed = kwargs["env"]
                    assert env_passed["_NT_SYMBOL_PATH"] == "srv*cache"

    def test_run_cdb_symbol_path_default_with_no_env(self):
        """When no symbol_path and _NT_SYMBOL_PATH is in os.environ as empty,
        it should be preserved (taken from os.environ.copy())."""
        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("mvp.cdb_runner.find_cdb", return_value=self.fake_cdb):
                with mock.patch("subprocess.run") as mock_run:
                    with mock.patch.object(builtins, "open") as mock_open:
                        with mock.patch(
                            "tempfile.NamedTemporaryFile"
                        ) as mock_tmpfile:
                            out_path = "C:/tmp/stdout.txt"
                            err_path = "C:/tmp/stderr.txt"

                            mock_out = mock.MagicMock()
                            mock_out.name = out_path
                            mock_err = mock.MagicMock()
                            mock_err.name = err_path
                            mock_out.__enter__.return_value = mock_out
                            mock_err.__enter__.return_value = mock_err
                            mock_tmpfile.side_effect = [mock_out, mock_err]

                            def open_side(path, mode="r", **kw):
                                if "w" in mode:
                                    return StringIO()
                                if str(path) == out_path:
                                    return StringIO("")
                                if str(path) == err_path:
                                    return StringIO("")
                                return StringIO("")

                            mock_open.side_effect = open_side

                            with mock.patch.dict(
                                os.environ, {"_NT_SYMBOL_PATH": "srv*cache"}
                            ):
                                run_cdb(
                                    dump_path=self.fake_dump,
                                    commands=["!analyze -v"],
                                    symbol_path="srv*override",
                                )

                    _, kwargs = mock_run.call_args
                    env_passed = kwargs["env"]
                    # Explicit symbol_path takes precedence.
                    assert env_passed["_NT_SYMBOL_PATH"] == "srv*override"


class TestRunCdbStderr:
    """Tests for stderr capture in run_cdb."""

    def test_run_cdb_stderr_captured(self):
        """CDB stderr output is appended to result with [CDB STDERR] marker."""
        fake_cdb = "C:/fake/cdb.exe"
        fake_dump = "C:/fake/crash.dmp"
        stderr_content = "WARNING: Symbol path validation failed"

        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("mvp.cdb_runner.find_cdb", return_value=fake_cdb):
                with mock.patch("subprocess.run") as mock_run:
                    with mock.patch.object(builtins, "open") as mock_open:
                        with mock.patch(
                            "tempfile.NamedTemporaryFile"
                        ) as mock_tmpfile:
                            out_path = "C:/tmp/stdout.txt"
                            err_path = "C:/tmp/stderr.txt"

                            mock_out = mock.MagicMock()
                            mock_out.name = out_path
                            mock_err = mock.MagicMock()
                            mock_err.name = err_path
                            mock_out.__enter__.return_value = mock_out
                            mock_err.__enter__.return_value = mock_err
                            mock_tmpfile.side_effect = [mock_out, mock_err]

                            def open_side(path, mode="r", **kw):
                                if "w" in mode:
                                    return StringIO()
                                if str(path) == out_path:
                                    return StringIO("CDB output line 1\nCDB output line 2")
                                if str(path) == err_path:
                                    return StringIO(stderr_content)
                                return StringIO("")

                            mock_open.side_effect = open_side

                            result = run_cdb(
                                dump_path=fake_dump,
                                commands=["!analyze -v"],
                            )

                    assert "[CDB STDERR]" in result
                    assert stderr_content in result


class TestRunCdbCommandLine:
    """Tests for CDB command-line construction."""

    def test_run_cdb_passes_commands_inline(self):
        """Commands are joined with semicolons and passed via -c."""
        fake_cdb = "C:/fake/cdb.exe"
        fake_dump = "C:/fake/crash.dmp"

        with mock.patch.object(Path, "is_file", return_value=True):
            with mock.patch("mvp.cdb_runner.find_cdb", return_value=fake_cdb):
                with mock.patch("subprocess.run") as mock_run:
                    with mock.patch.object(builtins, "open") as mock_open:
                        with mock.patch(
                            "tempfile.NamedTemporaryFile"
                        ) as mock_tmpfile:
                            out_path = "C:/tmp/stdout.txt"
                            err_path = "C:/tmp/stderr.txt"

                            mock_out = mock.MagicMock()
                            mock_out.name = out_path
                            mock_err = mock.MagicMock()
                            mock_err.name = err_path
                            mock_out.__enter__.return_value = mock_out
                            mock_err.__enter__.return_value = mock_err
                            mock_tmpfile.side_effect = [mock_out, mock_err]

                            def open_side(path, mode="r", **kw):
                                if "w" in mode:
                                    return StringIO()
                                if str(path) == out_path:
                                    return StringIO("output")
                                if str(path) == err_path:
                                    return StringIO("")
                                return StringIO("")

                            mock_open.side_effect = open_side

                            run_cdb(
                                dump_path=fake_dump,
                                commands=["!analyze -v", "k 50"],
                            )

                    args, _ = mock_run.call_args
                    cmd = args[0]
                    assert cmd[0] == fake_cdb
                    assert cmd[1] == "-z"
                    assert cmd[3] == "-c"
                    assert "!analyze -v" in cmd[4]
                    assert "k 50" in cmd[4]
                    assert "-lines" in cmd
                    assert "-noshell" in cmd


# ---------------------------------------------------------------------------
# Tests: command sets (structure)
# ---------------------------------------------------------------------------

class TestCommandsForSystemInfo:
    """Verify commands_for_system_info returns the expected command list."""

    def test_commands_for_system_info_structure(self):
        """Verify commands_for_system_info returns expected command list."""
        result = commands_for_system_info()
        assert isinstance(result, list)
        assert len(result) == 7
        assert result == [
            "vertarget",
            "!sysinfo smbios",
            "!cpuinfo",
            "!vm",
            "!memusage",
            "!envvar",
            ".time",
        ]


class TestCommandsForCrashAnalysis:
    """Verify commands_for_crash_analysis returns the expected command list."""

    def test_commands_for_crash_analysis_structure(self):
        """Verify commands_for_crash_analysis returns expected list."""
        result = commands_for_crash_analysis()
        assert isinstance(result, list)
        assert len(result) == 8
        assert result == [
            "!analyze -v",
            ".ecxr",
            "k 50",
            "~* k",
            "lm vm",
            "!locks",
            "!heap -s",
            "!address -summary",
        ]


class TestCommandsForFullAnalysis:
    """Verify commands_for_full_analysis combines both lists."""

    def test_commands_for_full_analysis_combines(self):
        """Full analysis commands equal system_info + crash_analysis concatenated."""
        result = commands_for_full_analysis()
        expected = commands_for_system_info() + commands_for_crash_analysis()
        assert result == expected
        assert len(result) == 15

    def test_commands_for_full_analysis_is_independent(self):
        """Mutating the returned list does not affect the source lists."""
        result = commands_for_full_analysis()
        result.append("extra")
        assert len(commands_for_full_analysis()) == 15
        assert len(commands_for_system_info()) == 7
        assert len(commands_for_crash_analysis()) == 8
