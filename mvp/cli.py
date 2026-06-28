"""CLI entry point — argument parsing and pipeline orchestration."""

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from .cdb_runner import find_cdb
from .collectors.binary_collector import BinaryCollector
from .collectors.config_collector import ConfigCollector
from .collectors.dmp_collector import DmpCollector
from .collectors.eventlog_collector import EventLogCollector
from .collectors.log_collector import LogCollector
from .collectors.source_collector import SourceCollector
from .collectors.symbol_collector import SymbolCollector
from .context import AnalysisContext
from .ai_client import analyze
from .reporter import generate_report, print_summary


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="dmp-analyzer",
        description="AI-powered Windows crash dump analysis tool",
    )

    # Required (single file or glob for batch)
    p.add_argument(
        "dump_file",
        nargs="+",
        help="Path to the .dmp file (or glob pattern with --batch)",
    )

    # Mode
    p.add_argument(
        "--batch",
        action="store_true",
        help="Batch mode: process multiple DMP files and produce a summary",
    )
    p.add_argument(
        "--batch-output",
        default=None,
        help="Batch summary report path (default: batch_summary.md)",
    )
    p.add_argument(
        "--correlate",
        action="store_true",
        help="Enable cross-DMP correlation analysis in batch mode"
             " (adds one extra AI call for comprehensive analysis)",
    )
    p.add_argument(
        "--workers", "-w",
        type=int,
        default=None,
        help="Number of parallel CDB workers (default: min(4, DMP count))",
    )
    p.add_argument(
        "--diff",
        nargs=2,
        default=None,
        metavar=("REPORT1", "REPORT2"),
        help="Compare two existing Markdown reports and produce a diff",
    )

    # Context inputs
    p.add_argument(
        "--exe-dir", "-e",
        help="Software deployment directory (for matching binaries, symbols, config, logs)",
    )
    p.add_argument(
        "--source-dir", "-s",
        help="Source code directory or Git repository path",
    )
    p.add_argument(
        "--log-dir", "-l",
        help="Log file directory (default: auto-detect from --exe-dir)",
    )
    p.add_argument(
        "--symbol-path", "-p",
        action="append", default=None,
        help="PDB symbol search path (can be specified multiple times)",
    )
    p.add_argument(
        "--system-logs",
        action="store_true",
        help="Collect Windows Event Log entries (requires admin privileges)",
    )

    # CDB options
    p.add_argument(
        "--cdb",
        default=None,
        help="Path to cdb.exe (default: auto-detect)",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="CDB execution timeout in seconds (default: 120)",
    )
    p.add_argument(
        "--no-cache",
        action="store_true",
        help="Skip CDB output cache, force re-run CDB",
    )
    p.add_argument(
        "--clear-cache",
        action="store_true",
        help="Clear CDB output cache and exit",
    )

    # Output options
    p.add_argument(
        "--output", "-o",
        default=None,
        help="Report output path (default: <dump_name>_report.md)",
    )
    p.add_argument(
        "--format", "-f",
        choices=["md", "html", "pdf"],
        default="md",
        help="Report format: md (Markdown), html, or pdf (default: md)",
    )
    p.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Suppress progress output (only print final report path)",
    )
    p.add_argument(
        "--json-only",
        action="store_true",
        help="Output only the structured context JSON, skip AI analysis",
    )
    p.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Verbose logging",
    )

    # AI options
    p.add_argument(
        "--provider",
        choices=["deepseek", "openai", "anthropic"],
        default="deepseek",
        help="AI backend provider (default: deepseek)",
    )
    p.add_argument(
        "--api-key",
        default=None,
        help="API key (or set DEEPSEEK_API_KEY / OPENAI_API_KEY / ANTHROPIC_API_KEY env var)",
    )
    p.add_argument(
        "--model",
        default=None,
        help="Model name (default: provider-specific, e.g. deepseek-chat)",
    )

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # -- Diff mode --
    if args.diff:
        from .diff import diff_reports
        report = diff_reports(args.diff[0], args.diff[1])
        out = args.output or "diff_report.md"
        Path(out).write_text(report, encoding="utf-8")
        print(f"\n[OK] Diff report saved: {out}")
        return 0

    # -- Clear cache and exit --
    if args.clear_cache:
        from .cache_manager import CacheManager
        cm = CacheManager()
        cm.clear()
        print(f"[OK] CDB cache cleared: {cm.cache_dir}")
        return 0

    # -- Build shared args --
    symbol_paths = args.symbol_path or []
    exe_dir = str(Path(args.exe_dir).resolve()) if args.exe_dir else None
    if exe_dir:
        symbol_paths.insert(0, exe_dir)
    source_dir = str(Path(args.source_dir).resolve()) if args.source_dir else None

    # -- Batch mode --
    if args.batch:
        from .batch import run_batch
        return run_batch(
            patterns=args.dump_file,
            exe_dir=exe_dir,
            source_dir=source_dir,
            symbol_paths=symbol_paths,
            cdb_path=args.cdb,
            timeout=args.timeout,
            provider=args.provider,
            api_key=args.api_key,
            model=args.model,
            json_only=args.json_only,
            verbose=args.verbose,
            output=args.batch_output,
            no_cache=args.no_cache,
            correlate=args.correlate,
            workers=args.workers,
        )

    # -- Single file mode --
    dump_path = Path(args.dump_file[0]).resolve()
    if not dump_path.is_file():
        print(f"[ERROR] DMP file not found: {args.dump_file[0]}")
        return 1

    if not dump_path.suffix.lower() in (".dmp", ".mdmp", ".hdmp"):
        print(f"[WARN] File extension is not .dmp, may not be a valid dump: "
              f"{dump_path.suffix}")

    # -- Verify CDB --
    try:
        cdb = find_cdb(args.cdb)
        if args.verbose:
            print(f"[OK] CDB: {cdb}")
    except FileNotFoundError as e:
        print(f"[ERROR] {e}")
        return 1

    # -- Init context --
    ctx = AnalysisContext(
        dump_path=str(dump_path),
        exe_dir=exe_dir,
        source_dir=source_dir,
        log_dir=str(Path(args.log_dir).resolve()) if args.log_dir else None,
        symbol_paths=symbol_paths,
        collected_at=datetime.now().isoformat(),
    )
    # Internal flag for system-logs
    ctx._collect_system_logs = args.system_logs  # type: ignore[attr-defined]

    # -- Run collectors --
    collectors = [
        DmpCollector(cdb_path=args.cdb, timeout=args.timeout,
                     no_cache=args.no_cache),
        BinaryCollector(),
        SymbolCollector(),
        LogCollector(),
        EventLogCollector(),
        SourceCollector(),
        ConfigCollector(),
    ]

    start_time = datetime.now()
    if not args.quiet:
        print(f"\n== Analyzing: {dump_path.name} ==\n")

    timings = {}
    for collector in collectors:
        t0 = datetime.now()
        if collector.is_applicable(ctx):
            if not args.quiet:
                print(f"  [{collector.name}] collecting...")
            try:
                ctx = collector.collect(ctx)
            except Exception as e:
                print(f"  [WARN] [{collector.name}] failed: {e}")
                if args.verbose:
                    import traceback
                    traceback.print_exc()
        else:
            if args.verbose:
                print(f"  [SKIP] [{collector.name}] not applicable")
        timings[collector.name] = (datetime.now() - t0).total_seconds()

    # -- Output context JSON --
    context_json = json.dumps(ctx.to_dict(), ensure_ascii=False, indent=2)

    if args.json_only:
        print(f"\n{'='*60}")
        print(context_json)
        return 0

    # -- AI Analysis --
    # Select specialized prompt template based on exception type
    from .template_selector import select_template
    exception_code = ctx.dmp.exception.code if ctx.dmp else ""
    try:
        prompt_template = select_template(exception_code)
    except FileNotFoundError as e:
        print(f"[ERROR] Cannot load prompt template: {e}")
        return 1

    print(f"\n  [AI] calling {args.provider} (model={args.model or 'default'}) ...")
    try:
        ai_result = analyze(
            context_json=context_json,
            prompt_template=prompt_template,
            provider=args.provider,
            api_key=args.api_key,
            model=args.model,
        )
    except Exception as e:
        print(f"[ERROR] AI analysis failed: {e}")
        return 1

    # -- Generate report --
    output_path = args.output or str(dump_path.with_suffix("")) + "_report.md"
    report = generate_report(context_json, ai_result, str(dump_path),
                             collected_at=ctx.collected_at)

    Path(output_path).write_text(report, encoding="utf-8")

    total_time = (datetime.now() - start_time).total_seconds()
    if not args.quiet:
        print(f"\n[OK] Report saved: {output_path}")
        print(f"     Total time: {total_time:.1f}s")
        if args.verbose:
            for name, sec in timings.items():
                print(f"       {name}: {sec:.1f}s")

    # -- HTML / PDF export --
    if args.format in ("html", "pdf"):
        html_path = output_path.replace(".md", ".html")
        from .reporter import md_to_html
        html = md_to_html(report)
        if args.format == "html":
            Path(html_path).write_text(html, encoding="utf-8")
            if not args.quiet:
                print(f"     HTML: {html_path}")
        elif args.format == "pdf":
            from .reporter import html_to_pdf
            pdf_path = output_path.replace(".md", ".pdf")
            try:
                html_to_pdf(html, pdf_path)
                if not args.quiet:
                    print(f"     PDF: {pdf_path}")
            except ImportError as e:
                print(f"  [WARN] {e}")

    # -- Print summary --
    print_summary(ai_result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
