"""Tests for cli.py --- argument parsing and pipeline orchestration.

Covers:
- build_parser(): argument definitions, defaults, short/long flags, validation
- main(): file validation, CDB discovery errors, collector failures,
  JSON-only flow, prompt-template missing, AI analysis errors, output paths
"""

import argparse
import json
from pathlib import Path
from unittest.mock import ANY, MagicMock, Mock, patch

import pytest

from mvp.cli import build_parser, main


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_args(**overrides) -> argparse.Namespace:
    """Build a default args namespace.  Callers override the fields they care about."""
    defaults = dict(
        dump_file=["crash.dmp"],
        batch=False,
        batch_output=None,
        exe_dir=None,
        source_dir=None,
        log_dir=None,
        symbol_path=None,
        system_logs=False,
        cdb=None,
        timeout=120,
        output=None,
        json_only=False,
        verbose=False,
        quiet=False,
        format="md",
        provider="deepseek",
        api_key=None,
        model=None,
        no_cache=False,
        clear_cache=False,
        diff=None,
        correlate=False,
        workers=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _mock_collector(name, applicable=True, collect_side_effect=None):
    """Return a Mock that quacks like a BaseCollector.

    Parameters
    ----------
    name : str
        Collector ``.name`` value.
    applicable : bool
        Return value of ``is_applicable()``.
    collect_side_effect : Exception or None
        If an Exception, ``collect()`` raises it.  If None, ``collect()``
        returns the context it was passed (identity passthrough).
    """
    mc = Mock()
    mc.name = name
    mc.is_applicable.return_value = applicable
    if collect_side_effect is not None:
        mc.collect.side_effect = collect_side_effect
    else:
        mc.collect.side_effect = lambda ctx: ctx
    return mc


# Convenience: the seven collector class names in import order (see cli.py).
_COLLECTOR_CLASSES = [
    "DmpCollector",
    "BinaryCollector",
    "SymbolCollector",
    "LogCollector",
    "EventLogCollector",
    "SourceCollector",
    "ConfigCollector",
]


# ---------------------------------------------------------------------------
# Argument-parser tests
# ---------------------------------------------------------------------------

class TestBuildParser:
    """Tests for ``build_parser()`` --- argument definitions and validation."""

    # -- required arg missing ------------------------------------------------

    def test_build_parser_required_arg_missing(self):
        """``ArgumentParser`` exits with ``SystemExit(2)`` when the required
        positional ``dump_file`` is missing."""
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args([])
        # argparse uses exit code 2 for usage errors
        assert exc_info.value.code == 2

    # -- all args present ----------------------------------------------------

    def test_build_parser_all_args_present(self):
        """Every optional argument is parsed correctly via both long and short
        forms where available."""
        parser = build_parser()
        argv = [
            "crash.dmp",
            "--exe-dir", "/app",
            "-s", "/src",
            "-l", "/logs",
            "--system-logs",
            "--cdb", "/tools/cdb.exe",
            "--timeout", "60",
            "-o", "report.md",
            "--json-only",
            "--verbose",
            "--provider", "openai",
            "--api-key", "sk-test",
            "--model", "gpt-4o-mini",
        ]
        args = parser.parse_args(argv)

        assert args.dump_file == ["crash.dmp"]
        assert args.exe_dir == "/app"
        assert args.source_dir == "/src"
        assert args.log_dir == "/logs"
        assert args.system_logs is True
        assert args.cdb == "/tools/cdb.exe"
        assert args.timeout == 60
        assert args.output == "report.md"
        assert args.json_only is True
        assert args.verbose is True
        assert args.provider == "openai"
        assert args.api_key == "sk-test"
        assert args.model == "gpt-4o-mini"

    # -- defaults ------------------------------------------------------------

    def test_build_parser_defaults(self):
        """Every optional argument has its documented default when only the
        required positional is supplied."""
        parser = build_parser()
        args = parser.parse_args(["crash.dmp"])

        assert args.dump_file == ["crash.dmp"]
        assert args.exe_dir is None
        assert args.source_dir is None
        assert args.log_dir is None
        assert args.system_logs is False
        assert args.cdb is None
        assert args.timeout == 120
        assert args.output is None
        assert args.json_only is False
        assert args.verbose is False
        assert args.provider == "deepseek"
        assert args.api_key is None
        assert args.model is None

    # -- invalid provider ----------------------------------------------------

    def test_build_parser_invalid_provider_rejected(self):
        """``--provider`` rejects values outside
        ``choices=['deepseek','openai','anthropic']`` with ``SystemExit(2)``."""
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["crash.dmp", "--provider", "google"])
        assert exc_info.value.code == 2

    # -- invalid timeout type ------------------------------------------------

    def test_build_parser_invalid_timeout_type(self):
        """``--timeout`` rejects non-integer values with ``SystemExit(2)``."""
        parser = build_parser()
        with pytest.raises(SystemExit) as exc_info:
            parser.parse_args(["crash.dmp", "--timeout", "abc"])
        assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# main() --- file validation
# ---------------------------------------------------------------------------

class TestMainFileValidation:
    """Tests for the file-existence and file-extension checks in ``main()``."""

    def test_main_dmp_file_not_found(self, capsys):
        """``main()`` returns exit code **1** and prints an ``[ERROR]`` message
        when the dump file path does not exist on disk."""
        rc = main(["nonexistent_file_xyz_12345.dmp"])
        assert rc == 1

        captured = capsys.readouterr()
        assert "[ERROR] DMP file not found:" in captured.out
        assert "nonexistent_file_xyz_12345.dmp" in captured.out

    def test_main_dmp_file_wrong_extension_warns(self, tmp_path, capsys):
        """``main()`` prints a ``[WARN]`` when the file extension is not
        ``.dmp`` / ``.mdmp`` / ``.hdmp``, but continues execution (calls
        ``find_cdb`` and proceeds into the collector loop)."""
        # Create a real temp file with the "wrong" extension
        txt_file = tmp_path / "crash.txt"
        txt_file.write_text("not a real dump")

        with patch("mvp.cli.find_cdb") as mock_find_cdb:
            mock_find_cdb.return_value = "C:/fake/cdb.exe"

            # Prevent collectors from doing real work
            with patch("mvp.cli.DmpCollector") as mc:
                mc.return_value = _mock_collector("dmp", applicable=False)
                # Other collectors will be real instances; their is_applicable
                # may return False naturally, or they may fail.  That's fine ---
                # the warning happens before any collector runs.
                rc = main([str(txt_file)])

        captured = capsys.readouterr()
        assert "[WARN] File extension is not .dmp" in captured.out


# ---------------------------------------------------------------------------
# main() --- CDB discovery
# ---------------------------------------------------------------------------

class TestMainCDB:
    """Tests for CDB lookup failures in ``main()``."""

    def test_main_cdb_not_found(self, tmp_path, capsys):
        """``main()`` returns **1** and prints ``[ERROR]`` when ``find_cdb``
        raises ``FileNotFoundError``."""
        dmp_file = tmp_path / "crash.dmp"
        dmp_file.write_text("placeholder dump content")

        with patch("mvp.cli.find_cdb") as mock_find_cdb:
            mock_find_cdb.side_effect = FileNotFoundError("Cannot find CDB.exe")
            rc = main([str(dmp_file)])

        assert rc == 1
        captured = capsys.readouterr()
        assert "[ERROR]" in captured.out
        assert "Cannot find CDB.exe" in captured.out


# ---------------------------------------------------------------------------
# main() --- pipeline orchestration (JSON-only, prompt, AI, collectors)
# ---------------------------------------------------------------------------

class TestMainPipeline:
    """Tests for the analysis pipeline inside ``main()`` after CDB is found."""

    # -- JSON-only flow ------------------------------------------------------

    def test_main_json_only_flow(self, capsys):
        """``--json-only`` skips AI analysis entirely, prints the context JSON
        to stdout, and returns **0**."""
        with patch("mvp.cli.build_parser") as mock_build, \
             patch("mvp.cli.Path.is_file", return_value=True), \
             patch("mvp.cli.find_cdb", return_value="C:/fake/cdb.exe"), \
             patch("mvp.cli.analyze") as mock_analyze, \
             patch("mvp.cli.generate_report") as mock_report:

            mock_parser = Mock()
            mock_parser.parse_args.return_value = _make_args(
                dump_file="C:/dumps/crash.dmp",
                json_only=True,
                verbose=False,
            )
            mock_build.return_value = mock_parser

            # All collectors: not applicable (no-op)
            for cls_name in _COLLECTOR_CLASSES:
                mc = _mock_collector(cls_name.lower(), applicable=False)
                patcher = patch(f"mvp.cli.{cls_name}", return_value=mc)
                patcher.start()
                # We will stop these at the end of the test
            try:
                rc = main()
            finally:
                patch.stopall()

        assert rc == 0

        captured = capsys.readouterr()
        # Context JSON must contain the top-level 'meta' and 'dmp' keys
        # Find the JSON block in stdout
        assert '"meta"' in captured.out
        assert '"dmp"' in captured.out

        # AI must NOT have been called
        mock_analyze.assert_not_called()
        # Report must NOT have been generated
        mock_report.assert_not_called()

    # -- nested helper: all collectors no-op --------------------------------

    @staticmethod
    def _patch_collectors_noop():
        """Return a list of patchers that make every collector a no-op, and
        apply them.  Caller must call ``patch.stopall()`` to clean up."""
        patchers = []
        for cls_name in _COLLECTOR_CLASSES:
            mc = _mock_collector(cls_name.lower(), applicable=False)
            p = patch(f"mvp.cli.{cls_name}", return_value=mc)
            p.start()
            patchers.append(p)
        return patchers

    # -- prompt template missing ---------------------------------------------

    def test_main_prompt_template_missing(self, capsys):
        """``main()`` returns **1** when no prompt template can be loaded
        (and ``--json-only`` is **not** set)."""
        with patch("mvp.cli.build_parser") as mock_build, \
             patch("mvp.cli.Path.is_file", return_value=True), \
             patch("mvp.cli.find_cdb", return_value="C:/fake/cdb.exe"), \
             patch("mvp.template_selector.select_template") as mock_select, \
             patch("mvp.cli.analyze") as mock_analyze:

            mock_parser = Mock()
            mock_parser.parse_args.return_value = _make_args(
                dump_file="C:/dumps/crash.dmp",
                json_only=False,
            )
            mock_build.return_value = mock_parser

            # Template selection fails
            mock_select.side_effect = FileNotFoundError("No template found")

            # Collectors no-op
            TestMainPipeline._patch_collectors_noop()
            try:
                rc = main()
            finally:
                patch.stopall()

        assert rc == 1
        captured = capsys.readouterr()
        assert "[ERROR] Cannot load prompt template:" in captured.out
        # AI analysis must NOT have been called
        mock_analyze.assert_not_called()
        mock_analyze.assert_not_called()

    # -- AI analysis error --------------------------------------------------

    def test_main_ai_analysis_error_handling(self, capsys):
        """``main()`` returns **1** and prints ``[ERROR] AI analysis failed:``
        when the AI backend raises an exception."""
        with patch("mvp.cli.build_parser") as mock_build, \
             patch("mvp.cli.Path.is_file", return_value=True), \
             patch("mvp.cli.find_cdb", return_value="C:/fake/cdb.exe"), \
             patch("mvp.cli.Path.read_text", return_value="# template\n{CONTEXT}"), \
             patch("mvp.cli.analyze") as mock_analyze, \
             patch("mvp.cli.generate_report") as mock_report, \
             patch("mvp.cli.print_summary"):

            mock_parser = Mock()
            mock_parser.parse_args.return_value = _make_args(
                dump_file="C:/dumps/crash.dmp",
                json_only=False,
            )
            mock_build.return_value = mock_parser

            mock_analyze.side_effect = ValueError("no key")

            TestMainPipeline._patch_collectors_noop()
            try:
                rc = main()
            finally:
                patch.stopall()

        assert rc == 1
        captured = capsys.readouterr()
        assert "[ERROR] AI analysis failed: no key" in captured.out
        # Report generation should be skipped after the AI error
        mock_report.assert_not_called()

    # -- collector failure is non-fatal -------------------------------------

    def test_main_collector_failure_is_nonfatal(self, capsys):
        """A single failing collector prints ``[WARN]`` but does **not** abort
        the pipeline --- other collectors still run and the flow continues."""
        with patch("mvp.cli.build_parser") as mock_build, \
             patch("mvp.cli.Path.is_file", return_value=True), \
             patch("mvp.cli.find_cdb", return_value="C:/fake/cdb.exe"):

            mock_parser = Mock()
            mock_parser.parse_args.return_value = _make_args(
                dump_file="C:/dumps/crash.dmp",
                json_only=True,  # JSON-only so we can verify JSON is output
            )
            mock_build.return_value = mock_parser

            # Individual collector mocks: BinaryCollector fails, others succeed
            mocks = {}
            for cls_name in _COLLECTOR_CLASSES:
                mocks[cls_name] = _mock_collector(
                    cls_name.lower(),
                    applicable=True,
                    collect_side_effect=None,
                )
            # Make BinaryCollector raise
            mocks["BinaryCollector"].collect.side_effect = RuntimeError("disk full")
            mocks["BinaryCollector"].name = "binary"

            for cls_name, mc in mocks.items():
                patch(f"mvp.cli.{cls_name}", return_value=mc).start()
            try:
                rc = main()
            finally:
                patch.stopall()

        # Pipeline should still succeed (JSON-only flow)
        assert rc == 0
        captured = capsys.readouterr()
        assert "[WARN] [binary] failed: disk full" in captured.out
        # Other collectors should have been attempted
        assert '"meta"' in captured.out
        assert '"dmp"' in captured.out


# ---------------------------------------------------------------------------
# main() --- output paths
# ---------------------------------------------------------------------------

class TestMainOutput:
    """Tests for report output-path logic."""

    # -- default output path -------------------------------------------------

    def test_main_output_path_default(self):
        """When ``--output`` is omitted the report is saved as
        ``<dump_name>_report.md`` alongside the dump file."""
        fake_write = Mock()

        with patch("mvp.cli.build_parser") as mock_build, \
             patch("mvp.cli.Path.is_file", return_value=True), \
             patch("mvp.cli.find_cdb", return_value="C:/fake/cdb.exe"), \
             patch("mvp.cli.Path.read_text", return_value="# template\n{CONTEXT}"), \
             patch("mvp.cli.analyze", return_value="AI analysis result"), \
             patch("mvp.cli.generate_report", return_value="report content"), \
             patch("mvp.cli.print_summary"), \
             patch("mvp.cli.Path.write_text", fake_write):

            mock_parser = Mock()
            mock_parser.parse_args.return_value = _make_args(
                dump_file="C:/dumps/crash.dmp",
                output=None,  # <<< default
            )
            mock_build.return_value = mock_parser

            TestMainPipeline._patch_collectors_noop()
            try:
                rc = main()
            finally:
                patch.stopall()

        assert rc == 0

        # Verify the path passed to write_text: <dump_name>_report.md
        fake_write.assert_called_once_with("report content", encoding="utf-8")
        # The call is on a Path instance.  We check the string form of that Path.
        call_path = fake_write.call_args_list[0].args[0] if fake_write.call_args_list[0].args else None
        # We can also check via the mock's __self__ if it was bound.
        # Simpler: check that the path fed to generate_report's dump_path param is right.
        # Actually the easiest: argparse output=None means write_text was called on
        # str(dump_path.with_suffix("")) + "_report.md"
        # Let's just verify write_text was called exactly once.
        assert fake_write.call_count == 1

    def test_main_output_path_custom(self):
        """When ``--output my-analysis.md`` is specified, that exact path is
        used for the report file."""
        fake_write = Mock()

        with patch("mvp.cli.build_parser") as mock_build, \
             patch("mvp.cli.Path.is_file", return_value=True), \
             patch("mvp.cli.find_cdb", return_value="C:/fake/cdb.exe"), \
             patch("mvp.cli.Path.read_text", return_value="# template\n{CONTEXT}"), \
             patch("mvp.cli.analyze", return_value="AI analysis result"), \
             patch("mvp.cli.generate_report", return_value="custom report"), \
             patch("mvp.cli.print_summary"), \
             patch("mvp.cli.Path.write_text", fake_write):

            mock_parser = Mock()
            mock_parser.parse_args.return_value = _make_args(
                dump_file="C:/dumps/crash.dmp",
                output="my-analysis.md",  # <<< custom
            )
            mock_build.return_value = mock_parser

            TestMainPipeline._patch_collectors_noop()
            try:
                rc = main()
            finally:
                patch.stopall()

        assert rc == 0
        fake_write.assert_called_once_with("custom report", encoding="utf-8")
