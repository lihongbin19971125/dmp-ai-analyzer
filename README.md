# DMP AI Analyzer

> AI-powered Windows crash dump analysis tool. Drop a `.dmp` file, get root cause analysis in seconds.

[![Rust](https://img.shields.io/badge/Rust-1.96%2B-orange)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-152%20passed-brightgreen)](https://github.com/Admin/dmp-ai-analyzer/actions)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## Features

- **CDB Two-Pass Analysis**: Extracts exception context, callstacks, modules, heap info, and locks
- **AI Root Cause Analysis**: DeepSeek / OpenAI / Anthropic backends with 6 specialized prompt templates
- **Memory Leak Detection**: 9 detection rules (high commit, virtual exhaustion, corruption, fragmentation...)
- **Batch Analysis**: Parallel CDB with rayon, max 10 DMPs
- **Desktop App**: Tauri v2 + React, drag-and-drop DMP files, config auto-save
- **Multi-Interface**: CLI binary, desktop GUI, C FFI, PyO3 Python binding

## Quick Start

### Desktop App

Download `dmp-tauri.exe` from [Releases](https://github.com/Admin/dmp-ai-analyzer/releases), double-click to run.

### CLI

```bash
dmp analyze crash.dmp                           # basic analysis
dmp analyze crash.dmp -e "C:\MyApp" -p "D:\Symbols"  # with symbols
dmp analyze *.dmp --batch --workers 4           # batch parallel
dmp diff report1.md report2.md                  # report comparison
```

### Rust Library

```rust
use dmp_core::*;
let result = analyze("crash.dmp", &AnalyzeOptions::default())?;
println!("{}", result.report_md);
```

## Requirements

| Component | Requirement |
|-----------|-------------|
| Windows | 10/11 |
| CDB | Windows SDK Debugging Tools |
| Rust (dev) | 1.96+ MSVC |
| VS (dev) | 2019+ C++ tools |

## Building from Source

```bash
git clone https://github.com/Admin/dmp-ai-analyzer.git
cd dmp-ai-analyzer

# Install dependencies
npm install

# Build CLI
cargo build --release -p dmp-cli

# Build desktop app
cargo tauri build

# Run tests
cargo test --workspace
```

## Project Structure

```
dmp-ai-analyzer/
├── crates/              # Rust workspace (6 crates)
│   ├── dmp-context/     # Data model (15 structs)
│   ├── dmp-parser/      # CDB output parser + memory analyzer
│   ├── dmp-engine/      # CDB, AI, cache, report, template, diff
│   ├── dmp-core/        # Public API + batch orchestration
│   ├── dmp-ffi/         # C FFI exports
│   ├── dmp-py/          # PyO3 Python binding
│   └── dmp-cli/         # CLI binary (dmp.exe)
├── src-tauri/           # Tauri desktop app backend
├── src/                 # React frontend
├── mvp/                 # Python MVP (preserved)
└── docs/                # Documentation
```

## Features

| Feature | Crate | Description |
|---------|-------|-------------|
| `http` | dmp-engine | AI API calls (reqwest + SChannel) |
| `parallel` | dmp-core | Parallel CDB batch (rayon) |

## License

MIT
