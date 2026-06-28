# DMP AI Analyzer — 使用说明书

> v1.0 | 发布日期: 2026-06-29

---

## 概述

**DMP AI Analyzer** 是 AI 驱动的 Windows 崩溃转储分析工具。提供 CLI 命令行 + 桌面 UI 双入口。

### 获取方式

| 产物 | 大小 | 说明 |
|------|:--:|------|
| `dmp.exe` | 4.8 MB | CLI 命令行，零依赖，复制即用 |
| `dmp-tauri.exe` | 13 MB | 桌面窗口，拖拽 DMP 即可分析 |
| `dmp_core.dll` | 2 MB | 嵌入库 (C/C++/Rust/Python 调用) |

### 核心能力

- **自动 CDB 两遍分析**: Pass 1 提取异常/调用栈，Pass 2 提取模块/堆/锁
- **AI 深度推理**: DeepSeek / OpenAI / Anthropic 三后端
- **6 种专用 Prompt**: 按异常类型自动选择模板
- **内存泄漏检测**: 9 项规则自动扫描
- **批量分析**: 最多 10 个 DMP 并行分析
- **配置持久化**: UI 设置自动保存，下次打开恢复
- **可嵌入**: C FFI / PyO3 / Tauri 三种接口

---

## 快速开始

### 桌面 UI (推荐)

双击 `dmp-tauri.exe` → 输入 DMP 路径 → 配置选项 → 点击 Analyze。

所有配置自动保存，下次打开无需重新输入。

### CLI 命令行

```bash
# 基本分析
dmp analyze crash.dmp

# 指定符号路径
dmp analyze crash.dmp -e "C:\MyApp" -p "D:\Symbols"

# JSON 输出（跳过 AI）
dmp analyze crash.dmp --json-only

# 批量分析
dmp analyze crash1.dmp crash2.dmp --batch

# 报告对比
dmp diff report1.md report2.md
```

### Rust 库

```rust
use dmp_core::*;
let opts = AnalyzeOptions { json_only: true, timeout_secs: 120, ..Default::default() };
let result = analyze(r"crash.dmp", &opts)?;
println!("{}", result.context_json);
```

### Python 绑定

```python
import _core
result = _core.analyze("crash.dmp", exe_dir="C:\\MyApp", json_only=True)
print(result.context_json)
```

---

## CLI 参数

| 参数 | 简写 | 说明 | 默认 |
|------|------|------|------|
| `<dump_file...>` | | DMP 文件路径 | 必需 |
| `-e, --exe-dir` | -e | EXE 目录 (符号路径) | — |
| `-p, --symbol-path` | -p | PDB 目录 (可多次) | — |
| `-o, --output` | -o | 报告输出路径 | `<dmp>_report.md` |
| `--format` | | md / html / pdf | md |
| `--provider` | | deepseek / openai / anthropic | deepseek |
| `--api-key` | | API Key | 环境变量 |
| `--model` | | 模型名 | provider 默认 |
| `--timeout` | | CDB 超时秒数 | 120 |
| `-w, --workers` | -w | 并行数 | 0 (auto) |
| `--batch` | | 批量模式 | 关闭 |
| `--json-only` | | 仅 JSON，跳过 AI | 关闭 |
| `-q, --quiet` | -q | 静默模式 | 关闭 |
| `--no-cache` | | 跳过 CDB 缓存 | 关闭 |

---

## 环境要求

| 组件 | 要求 |
|------|------|
| 操作系统 | Windows 10/11 |
| Windows SDK | Debugging Tools (CDB) |
| Rust 工具链 | 1.96+ MSVC (仅开发) |
| Python | 3.12+ (仅 dmp-py) |
| VS 2019+ | C++ 工具 (仅开发) |

---

## AI 配置

```bash
set DEEPSEEK_API_KEY=sk-xxx
set OPENAI_API_KEY=sk-xxx
set ANTHROPIC_API_KEY=sk-ant-xxx
```

或在 UI 中输入（自动保存到 `%LOCALAPPDATA%\dmp-analyzer\settings.json`）。

---

## 项目仓库

```
d:\code\dmp\                    # 本地 git 仓库
├── dmp.exe                     # CLI 工具 (target/release/)
├── dmp-tauri.exe               # 桌面应用 (target/release/)
├── crates/                     # Rust workspace (8 crates)
├── src-tauri/                  # Tauri 后端
├── src/                        # React 前端
├── mvp/                        # Python MVP (保留)
├── docs/                       # 文档
└── Cargo.toml                  # workspace 定义
```
