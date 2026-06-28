//! DMP AI Analyzer — Rust CLI
//!
//! Entry point for the `dmp` command-line tool.

mod args;

use args::{Command, OutputFormat};
use std::time::Instant;

fn main() {
    let start = Instant::now();

    let cli = match args::parse() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    };

    match cli.command {
        Command::Help => {
            println!("{}", args::usage());
        }
        Command::Version => {
            println!("dmp {}", env!("CARGO_PKG_VERSION"));
            println!("DMP AI Analyzer — Rust Edition");
            println!("https://github.com/user/dmp");
        }
        Command::Diff { report1, report2 } => {
            match dmp_engine::diff::diff_reports(
                std::path::Path::new(&report1),
                std::path::Path::new(&report2),
            ) {
                Ok(diff) => println!("{}", diff),
                Err(e) => {
                    eprintln!("Diff failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Command::Analyze(a) => {
            run_analyze(a, start);
        }
    }
}

fn run_analyze(a: args::AnalyzeArgs, start: Instant) {
    let provider = match a.provider.to_lowercase().as_str() {
        "openai" => dmp_core::AiProvider::OpenAI,
        "anthropic" => dmp_core::AiProvider::Anthropic,
        _ => dmp_core::AiProvider::DeepSeek,
    };

    let mut symbol_paths = a.symbol_paths.clone();
    if let Some(ref exe) = a.exe_dir {
        symbol_paths.insert(0, exe.clone());
    }

    let opts = dmp_core::AnalyzeOptions {
        exe_dir: a.exe_dir.clone(),
        source_dir: None,
        symbol_paths,
        provider,
        api_key: a.api_key.clone(),
        model: a.model.clone(),
        timeout_secs: a.timeout,
        workers: a.workers,
        no_cache: a.no_cache,
        json_only: a.json_only,
    };

    if a.batch || a.files.len() > 1 {
        run_batch(&a, &opts, start);
    } else {
        run_single(&a, &opts, start);
    }
}

fn run_single(a: &args::AnalyzeArgs, opts: &dmp_core::AnalyzeOptions, start: Instant) {
    let dump_path = &a.files[0];

    if !a.quiet {
        eprintln!("Analyzing: {}", dump_path);
    }

    match dmp_core::analyze(dump_path, opts) {
        Ok(result) => {
            let elapsed = start.elapsed();

            if a.json_only {
                println!("{}", result.context_json);
            } else {
                // Write report
                let default_name = format!("{}_report.md",
                    std::path::Path::new(dump_path)
                        .file_stem()
                        .map(|s| s.to_string_lossy())
                        .unwrap_or_else(|| "analysis".into()));
                let output_path = a.output.as_deref().unwrap_or(&default_name);

                let content = match a.format {
                    OutputFormat::Md => result.report_md,
                    OutputFormat::Html => result.report_html,
                    OutputFormat::Pdf => {
                        let html_output = output_path.replace(".pdf", ".html");
                        let _ = std::fs::write(&html_output, &result.report_html);
                        result.report_html
                    }
                };

                if let Err(e) = std::fs::write(output_path, &content) {
                    eprintln!("Failed to write report: {}", e);
                    std::process::exit(1);
                }

                if a.quiet {
                    println!("{}", output_path);
                } else {
                    eprintln!("Report saved: {}", output_path);
                    eprintln!("Total time: {:.1}s", elapsed.as_secs_f64());
                }
            }
        }
        Err(e) => {
            eprintln!("Analysis failed: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_batch(args: &args::AnalyzeArgs, opts: &dmp_core::AnalyzeOptions, start: Instant) {
    if !args.quiet {
        eprintln!("Batch analyzing {} DMPs...", args.files.len());
    }

    match dmp_core::analyze_batch(&args.files, opts) {
        Ok(batch) => {
            let elapsed = start.elapsed();

            // Write summary
            let summary_path = args.output.as_deref().unwrap_or("batch_summary.md");
            if let Err(e) = std::fs::write(summary_path, &batch.summary_md) {
                eprintln!("Failed to write summary: {}", e);
            }

            if !args.quiet {
                eprintln!("Summary saved: {}", summary_path);
                eprintln!("Total time: {:.1}s ({} DMPs)", elapsed.as_secs_f64(), batch.results.len());
            } else {
                println!("{}", summary_path);
            }
        }
        Err(e) => {
            eprintln!("Batch analysis failed: {}", e);
            std::process::exit(1);
        }
    }
}