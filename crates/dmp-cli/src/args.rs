//! Command-line argument parsing (pure std::env::args, no clap needed).

#[derive(Debug)]
pub struct CliArgs {
    pub command: Command,
}

#[derive(Debug)]
pub enum Command {
    Analyze(AnalyzeArgs),
    Diff { report1: String, report2: String },
    Help,
    Version,
}

#[derive(Debug)]
pub struct AnalyzeArgs {
    pub files: Vec<String>,
    pub exe_dir: Option<String>,
    pub symbol_paths: Vec<String>,
    pub output: Option<String>,
    pub format: OutputFormat,
    pub provider: String,
    pub api_key: Option<String>,
    pub model: Option<String>,
    pub timeout: u64,
    pub workers: usize,
    pub batch: bool,
    pub json_only: bool,
    pub quiet: bool,
    pub no_cache: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum OutputFormat {
    Md,
    Html,
    Pdf,
}

/// Parse command-line arguments.
pub fn parse() -> Result<CliArgs, String> {
    let args: Vec<String> = std::env::args().collect();
    parse_args(&args)
}

fn parse_args(args: &[String]) -> Result<CliArgs, String> {
    if args.len() < 2 {
        return Err(usage());
    }

    let cmd = &args[1];

    match cmd.as_str() {
        "--help" | "-h" => Ok(CliArgs { command: Command::Help }),
        "--version" | "-V" => Ok(CliArgs { command: Command::Version }),

        "analyze" => parse_analyze(&args[2..]),
        "diff" => parse_diff(&args[2..]),

        _ => {
            // If first arg is a .dmp file, treat as analyze
            if cmd.ends_with(".dmp") || cmd.ends_with(".mdmp") || cmd.ends_with(".hdmp") {
                parse_analyze(&args[1..])
            } else {
                Err(format!("Unknown command: {}\n\n{}", cmd, usage()))
            }
        }
    }
}

fn parse_analyze(args: &[String]) -> Result<CliArgs, String> {
    let mut files = Vec::new();
    let mut exe_dir = None;
    let mut symbol_paths = Vec::new();
    let mut output = None;
    let mut format = OutputFormat::Md;
    let mut provider = String::from("deepseek");
    let mut api_key = None;
    let mut model = None;
    let mut timeout: u64 = 120;
    let mut workers: usize = 0;
    let mut batch = false;
    let mut json_only = false;
    let mut quiet = false;
    let mut no_cache = false;

    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        match arg.as_str() {
            "--help" | "-h" => return Ok(CliArgs { command: Command::Help }),

            "--exe-dir" | "-e" => {
                i += 1;
                if i >= args.len() { return Err("--exe-dir requires a value".into()); }
                exe_dir = Some(args[i].clone());
            }
            "--symbol-path" | "-p" => {
                i += 1;
                if i >= args.len() { return Err("--symbol-path requires a value".into()); }
                symbol_paths.push(args[i].clone());
            }
            "--output" | "-o" => {
                i += 1;
                if i >= args.len() { return Err("--output requires a value".into()); }
                output = Some(args[i].clone());
            }
            "--format" => {
                i += 1;
                if i >= args.len() { return Err("--format requires a value (md|html|pdf)".into()); }
                format = match args[i].to_lowercase().as_str() {
                    "md" | "markdown" => OutputFormat::Md,
                    "html" => OutputFormat::Html,
                    "pdf" => OutputFormat::Pdf,
                    f => return Err(format!("Unknown format: {}. Use md, html, or pdf.", f)),
                };
            }
            "--provider" => {
                i += 1;
                if i >= args.len() { return Err("--provider requires a value".into()); }
                provider = args[i].clone();
            }
            "--api-key" => {
                i += 1;
                if i >= args.len() { return Err("--api-key requires a value".into()); }
                api_key = Some(args[i].clone());
            }
            "--model" => {
                i += 1;
                if i >= args.len() { return Err("--model requires a value".into()); }
                model = Some(args[i].clone());
            }
            "--timeout" => {
                i += 1;
                if i >= args.len() { return Err("--timeout requires a value".into()); }
                timeout = args[i].parse().map_err(|_| format!("Invalid timeout: {}", args[i]))?;
            }
            "--workers" | "-w" => {
                i += 1;
                if i >= args.len() { return Err("--workers requires a value".into()); }
                workers = args[i].parse().map_err(|_| format!("Invalid workers: {}", args[i]))?;
            }
            "--batch" => batch = true,
            "--json-only" => json_only = true,
            "--quiet" | "-q" => quiet = true,
            "--no-cache" => no_cache = true,

            _ => {
                if arg.starts_with('-') {
                    return Err(format!("Unknown flag: {}", arg));
                }
                files.push(arg.clone());
            }
        }
        i += 1;
    }

    if files.is_empty() {
        return Err("No DMP file specified.\n\n".to_string() + &usage());
    }

    Ok(CliArgs {
        command: Command::Analyze(AnalyzeArgs {
            files, exe_dir, symbol_paths, output, format,
            provider, api_key, model, timeout, workers,
            batch, json_only, quiet, no_cache,
        }),
    })
}

fn parse_diff(args: &[String]) -> Result<CliArgs, String> {
    let files: Vec<&String> = args.iter().filter(|a| !a.starts_with('-')).collect();
    if files.len() != 2 {
        return Err("diff requires exactly 2 report files.\n\nUsage: dmp diff <report1.md> <report2.md>".into());
    }
    Ok(CliArgs {
        command: Command::Diff {
            report1: files[0].clone(),
            report2: files[1].clone(),
        },
    })
}

pub fn usage() -> String {
    r"DMP AI Analyzer — Rust Edition

Usage:
  dmp analyze <dump_file...> [options]
  dmp diff <report1.md> <report2.md>
  dmp --help
  dmp --version

Arguments:
  <dump_file...>        One or more .dmp files to analyze

Options:
  -e, --exe-dir <dir>       EXE directory (auto-added as symbol path)
  -p, --symbol-path <dir>   PDB symbol directory (repeatable)
  -o, --output <path>       Report output path (default: <dmp>_report.md)
  --format <md|html|pdf>    Report format (default: md)
  --provider <name>         AI provider: deepseek|openai|anthropic (default: deepseek)
  --api-key <key>           API key (or set env var)
  --model <name>            Model name (default: provider-specific)
  --timeout <secs>          CDB timeout in seconds (default: 120)
  -w, --workers <n>         Parallel workers for batch (default: 0 = auto)
  --batch                   Batch mode: analyze multiple DMPs with summary
  --json-only               Output context JSON only, skip AI analysis
  -q, --quiet               Quiet mode: only print report path
  --no-cache                Skip CDB output cache

Environment:
  DEEPSEEK_API_KEY          DeepSeek API key
  OPENAI_API_KEY            OpenAI API key
  ANTHROPIC_API_KEY         Anthropic API key
  AI_API_KEY                Fallback API key for any provider
  CDB_PATH                  Path to cdb.exe (auto-detected otherwise)
".to_string()
}

// ═══════════════════════════════════════════════════════════════
// Unit tests for argument parsing
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(cmdline: &str) -> Result<CliArgs, String> {
        let args: Vec<String> = std::iter::once("dmp".to_string())
            .chain(cmdline.split_whitespace().map(String::from))
            .collect();
        parse_args(&args)
    }

    #[test]
    fn test_help() {
        let r = parse("--help").unwrap();
        assert!(matches!(r.command, Command::Help));
    }

    #[test]
    fn test_version() {
        let r = parse("--version").unwrap();
        assert!(matches!(r.command, Command::Version));
    }

    #[test]
    fn test_analyze_single_file() {
        let r = parse("analyze crash.dmp").unwrap();
        match r.command {
            Command::Analyze(a) => {
                assert_eq!(a.files, vec!["crash.dmp"]);
                assert_eq!(a.provider, "deepseek");
                assert_eq!(a.timeout, 120);
                assert!(!a.batch);
                assert!(!a.json_only);
            }
            _ => panic!("Expected Analyze command"),
        }
    }

    #[test]
    fn test_analyze_shortcut_no_analyze_keyword() {
        // "dmp crash.dmp" should work without the "analyze" keyword
        let r = parse("crash.dmp").unwrap();
        match r.command {
            Command::Analyze(a) => {
                assert_eq!(a.files, vec!["crash.dmp"]);
            }
            _ => panic!("Expected Analyze command"),
        }
    }

    #[test]
    fn test_analyze_batch() {
        let r = parse("analyze crash1.dmp crash2.dmp --batch").unwrap();
        match r.command {
            Command::Analyze(a) => {
                assert_eq!(a.files.len(), 2);
                assert!(a.batch);
            }
            _ => panic!("Expected Analyze command"),
        }
    }

    #[test]
    fn test_analyze_full_options() {
        let r = parse("analyze crash.dmp -e C:\\MyApp -p D:\\Symbols -p E:\\PDB \
            --format pdf --provider openai --api-key sk-test --model gpt-4o \
            --timeout 300 --workers 4 --json-only --quiet --no-cache").unwrap();

        match r.command {
            Command::Analyze(a) => {
                assert_eq!(a.files, vec!["crash.dmp"]);
                assert_eq!(a.exe_dir, Some("C:\\MyApp".into()));
                assert_eq!(a.symbol_paths, vec!["D:\\Symbols", "E:\\PDB"]);
                assert_eq!(a.format, OutputFormat::Pdf);
                assert_eq!(a.provider, "openai");
                assert_eq!(a.api_key, Some("sk-test".into()));
                assert_eq!(a.model, Some("gpt-4o".into()));
                assert_eq!(a.timeout, 300);
                assert_eq!(a.workers, 4);
                assert!(a.json_only);
                assert!(a.quiet);
                assert!(a.no_cache);
            }
            _ => panic!("Expected Analyze command"),
        }
    }

    #[test]
    fn test_analyze_default_provider() {
        let r = parse("analyze crash.dmp").unwrap();
        match r.command {
            Command::Analyze(a) => {
                assert_eq!(a.provider, "deepseek");
            }
            _ => panic!("Expected Analyze"),
        }
    }

    #[test]
    fn test_output_format_variants() {
        // md (default, no --format flag)
        let r = parse("analyze crash.dmp").unwrap();
        if let Command::Analyze(a) = r.command { assert_eq!(a.format, OutputFormat::Md); }

        // html
        let r = parse("analyze crash.dmp --format html").unwrap();
        if let Command::Analyze(a) = r.command { assert_eq!(a.format, OutputFormat::Html); }

        // pdf
        let r = parse("analyze crash.dmp --format pdf").unwrap();
        if let Command::Analyze(a) = r.command { assert_eq!(a.format, OutputFormat::Pdf); }
    }

    #[test]
    fn test_invalid_format() {
        let r = parse("analyze crash.dmp --format docx");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Unknown format"));
    }

    #[test]
    fn test_missing_dump_file() {
        let r = parse("analyze --json-only");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("No DMP file"));
    }

    #[test]
    fn test_unknown_flag() {
        let r = parse("analyze crash.dmp --invalid-flag");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("Unknown flag"));
    }

    #[test]
    fn test_diff_two_files() {
        let r = parse("diff report1.md report2.md").unwrap();
        match r.command {
            Command::Diff { report1, report2 } => {
                assert_eq!(report1, "report1.md");
                assert_eq!(report2, "report2.md");
            }
            _ => panic!("Expected Diff command"),
        }
    }

    #[test]
    fn test_diff_requires_two_files() {
        let r = parse("diff report1.md");
        assert!(r.is_err());
        assert!(r.unwrap_err().contains("exactly 2"));
    }

    #[test]
    fn test_exe_dir_becomes_symbol_path() {
        // In analyze(), exe_dir is prepended to symbol_paths.
        // The args parser just stores them; the merge happens in main.rs
        let r = parse("analyze crash.dmp -e C:\\MyApp -p D:\\Symbols").unwrap();
        if let Command::Analyze(a) = r.command {
            assert_eq!(a.exe_dir, Some("C:\\MyApp".into()));
            assert_eq!(a.symbol_paths, vec!["D:\\Symbols"]);
        }
    }

    #[test]
    fn test_short_flags() {
        let r = parse("analyze crash.dmp -e C:\\App -p D:\\PDB -o out.md -w 2 -q").unwrap();
        if let Command::Analyze(a) = r.command {
            assert_eq!(a.exe_dir, Some("C:\\App".into()));
            assert_eq!(a.symbol_paths, vec!["D:\\PDB"]);
            assert_eq!(a.output, Some("out.md".into()));
            assert_eq!(a.workers, 2);
            assert!(a.quiet);
        }
    }
}
