# DMP AI Analyzer — 使用说明书

> 版本: v0.3.0
> 更新日期: 2026-06-28

---

## 目录

1. [概述](#概述)
2. [环境要求](#环境要求)
3. [安装](#安装)
4. [快速开始](#快速开始)
5. [命令行参数详解](#命令行参数详解)
6. [使用场景](#使用场景)
7. [输出说明](#输出说明)
8. [AI 后端配置](#ai-后端配置)
9. [常见问题](#常见问题)
10. [附录](#附录)

---

## 概述

**DMP AI Analyzer** 是一个 AI 驱动的 Windows 崩溃转储文件 (.dmp) 自动分析工具。

### 核心能力

1. **自动调用 Windows 调试器 (CDB)** 从 DMP 中提取关键信息（两遍策略）
2. **自动收集关联上下文**：二进制版本、符号文件、应用日志、系统事件、源码、配置
3. **将完整上下文数据喂给 AI** (DeepSeek/OpenAI/Claude) 进行深度推理
4. **将完整上下文数据喂给 AI** (DeepSeek/OpenAI/Claude) 进行深度推理
5. **输出 Markdown / HTML / PDF 报告**
6. **批量分析**：多 DMP 汇总 + 异常聚类 + 关联分析（≤10 DMP）
7. **报告对比**：两份报告差异对比（异常/调用栈/模块/系统环境）

### 关键设计原则

- **系统信息从 DMP 内部提取**，而非分析机器 — 崩溃机器的真实 CPU/内存/OS 状态
- **符号路径由用户显式指定**，不自动连接微软符号服务器（适应现场网络受限环境）
- **增量采集架构** — 有 EXE 目录则分析二进制，有源码则定位代码，无则降级

### 当前版本能力

| 维度 | 数值 |
|------|------|
| 语言 | Python (MVP) + **Rust** (核心引擎) |
| 采集器 | 7 个 (DMP / 二进制 / 符号 / 日志 / 事件日志 / 源码 / 配置) |
| AI 后端 | DeepSeek / OpenAI / Anthropic |
| AI Prompt | 6 种专用模板（按异常类型自动选择） |
| 异常码覆盖 | 40+ 种 |
| 报告格式 | Markdown + HTML + PDF |
| 内存分析 | 9 项泄漏检测规则 + 堆/虚拟地址分析 |
| 批量分析 | glob + 关联分析（≤10 DMP） |
| 并行 CDB | rayon 线程池 |
| 报告对比 | --diff 两份报告差异对比 |
| CDB 缓存 | SHA256 + 200MB LRU |
| Rust 测试 | 124 passed, 0 failures (6 crates) |
| Python 测试 | 283 passed (15 files) |
| **嵌入能力** | C FFI + PyO3 绑定 |

---

## 环境要求

| 组件 | 要求 | 说明 |
|------|------|------|
| 操作系统 | Windows 10/11 | 仅分析端需要 Windows (CDB 依赖) |
| Windows SDK | 10.0.22621+ | 提供 CDB.exe 调试器 |
| Python | 3.11+ | 运行 MVP |
| AI API Key | DeepSeek / OpenAI / Claude | 三选一即可 |
| 权限 | 普通用户 | `--system-logs` 需要管理员权限 |

### 安装 Windows SDK 调试工具

如果系统上没有 CDB.exe:

1. 下载 [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/)
2. 安装时勾选 **"Debugging Tools for Windows"**
3. 安装后 CDB.exe 位于:
   - `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe` (64位)
   - `C:\Program Files (x86)\Windows Kits\10\Debuggers\x86\cdb.exe` (32位)

---

## 安装

```bash
# 1. 进入项目目录
cd d:\code\dmp

# 2. 安装 Python 依赖
pip install -r requirements.txt
# 依赖: openai>=1.0, anthropic>=0.30, pefile>=2023.0

# 3. 验证安装
python -m mvp --help
```

---

## Rust 核心引擎 (v0.3.0 新增)

除了 Python CLI，DMP AI Analyzer 现在提供 Rust 核心引擎，可作为库嵌入任何语言。

### Cargo 依赖

```toml
[dependencies]
dmp-core = { path = "crates/dmp-core", features = ["http", "parallel"] }
```

### Rust API

```rust
use dmp_core::*;

// 单 DMP 分析
let opts = AnalyzeOptions {
    exe_dir: Some(r"C:\MyApp".into()),
    symbol_paths: vec![r"D:\Symbols".into()],
    provider: AiProvider::DeepSeek,
    timeout_secs: 120,
    json_only: false,
    ..Default::default()
};

let result = analyze(r"C:\dumps\crash.dmp", &opts)?;
println!("{}", result.report_md);

// 批量分析
let patterns = vec![
    r"C:\dumps\crash1.dmp".into(),
    r"C:\dumps\crash2.dmp".into(),
];
let batch = analyze_batch(&patterns, &opts)?;
println!("{}", batch.summary_md);
```

### Python 绑定 (PyO3)

```python
import _core  # PyO3 native module

result = _core.analyze(
    r"C:\dumps\crash.dmp",
    exe_dir=r"C:\MyApp",
    symbol_paths=[r"D:\Symbols"],
    provider="deepseek",
    json_only=True,  # 跳过 AI，仅返回结构化数据
)

print(result.report_md)
print(result.context_json)
```

### C FFI

```c
// dmp_analyze 可从 C/C++/C#/Java 调用
typedef struct {
    char* context_json;
    char* ai_analysis;
    char* report_md;
    char* error;
} DmpResult;

DmpResult result = dmp_analyze("crash.dmp");
// 使用完毕后: dmp_result_free(&result);
```

### Build 要求

| 组件 | 要求 |
|------|------|
| Rust 工具链 | 1.96+ (stable-x86_64-pc-windows-msvc) |
| VS 2019+ | C++ 编译工具 (MSVC) |
| Python 3.12+ | 仅 dmp-py 需要 |
| Windows SDK | 10.0.19041+ (CDB 调试器) |

### Cargo Features

| Feature | Crate | 说明 |
|---------|-------|------|
| `http` | dmp-engine | AI API 调用 (reqwest + native-tls) |
| `parallel` | dmp-core | 并行 CDB 批量分析 (rayon) |

```bash
# 编译所有 feature
cargo build --release --features "http,parallel"

# 运行全部 124 测试
cargo test --workspace --features "http,parallel"
```

---

## 快速开始 (Python CLI)

### 最简用法 (仅 DMP 基础分析)

```bash
python -m mvp "C:\path\to\crash.dmp"
```

**采集内容**: DMP 核心数据（异常、调用栈、模块、系统信息）

**预期输出**:
```
== Analyzing: crash.dmp ==

  [dmp] collecting...  (12.3s)
  [binary] collecting...  (2.1s)
  [symbol] collecting...  (0.5s)

  [AI] calling deepseek (model=deepseek-chat) ...

[OK] Report saved: crash_report.md
     Total time: 45.2s
```

### 推荐用法 (指定 EXE 目录)

```bash
# 现场维护人员 — 指定软件部署目录
python -m mvp crash.dmp --exe-dir "C:\Program Files\MyApp"
```

**额外采集**:
- 匹配 DMP 中的模块到磁盘文件，提取版本号和 SHA256 哈希
- 从 System32/SysWOW64 自动补全系统模块路径
- 搜索 .pdb 符号文件 (EXE 目录优先)
- 自动发现应用日志 (EXE 目录 + 父目录 + AppData + TEMP)
- 读取配置文件 (脱敏后)

### 开发者用法

```bash
# 开发者 — 额外指定源码路径
python -m mvp crash.dmp \
    --exe-dir "C:\Program Files\MyApp" \
    --source-dir "D:\git\myapp"
```

**额外采集**:
- 在源码目录中匹配调用栈里的源文件
- 读取崩溃位置前后代码
- 查看 git log 近期修改记录（仅崩溃相关文件）
- 检查工作区是否有未提交修改

### 指定 PDB 符号路径

```bash
# PDB 不在 EXE 目录下 — 单独指定符号路径（可多次使用）
python -m mvp crash.dmp --exe-dir "C:\Program Files\MyApp" \
    -p "D:\Symbols\v1.2.3" \
    -p "\\server\pdbs\MyApp"
```

**效果**: 14 帧完整调用栈（含函数名+源码行号），vs 不指定时仅显示模块+偏移量。

> **注意**: 工具**不会**自动连接微软符号服务器。所有符号路径由用户通过 `-p` 显式指定。
> `--exe-dir` 自动作为首个符号搜索路径。

### 批量分析

```bash
# 一次分析多个 DMP，生成汇总 + 每个单独报告
python -m mvp "C:\CrashDumps\*.dmp" --batch --exe-dir "C:\MyApp" -p "D:\Symbols"

# 显式列出文件
python -m mvp crash1.dmp crash2.dmp --batch --exe-dir "C:\MyApp"
```

**输出**: 批量汇总报告包含:
- 概览表（每个 DMP 一行：异常、模块、根因）
- 异常聚类（相同类型归组统计）
- 模块崩溃频率统计
- 时间线（按崩溃时间排序）
- 链接到每个 DMP 的详细报告

### HTML 报告导出

```bash
python -m mvp crash.dmp --exe-dir "C:\MyApp" --format html
```

**输出**: `crash_report.html` — 独立 HTML 文件，内嵌 CSS 样式，可直接在浏览器中查看。

### 静默模式

```bash
# 只输出最终报告路径，适合脚本调用
python -m mvp crash.dmp -q
```

---

## 命令行参数详解

```
python -m mvp <dump_file...> [options]
```

### 必需参数

| 参数 | 说明 |
|------|------|
| `dump_file...` | 一个或多个 .dmp 文件路径或 glob 模式 |

单文件模式: `python -m mvp crash.dmp`
批量模式: `python -m mvp *.dmp --batch`

### 模式选择

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--batch` | 批量模式：处理多个 DMP，生成汇总报告 | 关闭 |
| `--batch-output` | 批量汇总报告路径 | `batch_summary.md` |
| `--correlate` | 批量模式下启用跨 DMP 关联分析（调用栈相似度/共因/版本交叉/频率趋势） | 关闭 |
| `--diff R1 R2` | 对比两份 Markdown 报告，输出差异 | — |

### 上下文输入

| 参数 | 简写 | 说明 | 推荐度 |
|------|------|------|--------|
| `--exe-dir` | `-e` | 软件部署目录，也作为首个符号搜索路径 | ⭐⭐⭐⭐⭐ |
| `--symbol-path` | `-p` | PDB 符号搜索路径，可多次指定追加 | ⭐⭐⭐⭐⭐ |
| `--source-dir` | `-s` | 源码路径或 Git 仓库 | ⭐⭐⭐⭐ |
| `--log-dir` | `-l` | 日志目录 (默认从 exe-dir 自动推断) | ⭐⭐⭐ |
| `--system-logs` | | 采集 Windows 事件日志 (需管理员权限) | ⭐⭐ |
| `--cdb` | | CDB.exe 路径 (默认自动检测) | ⭐ |

### 输出选项

| 参数 | 简写 | 说明 | 默认值 |
|------|------|------|--------|
| `--output` | `-o` | 报告输出路径 | `<dmp>_report.md` |
| `--format` | `-f` | 报告格式: `md` / `html` / `pdf` | `md` |
| `--quiet` | `-q` | 静默模式，仅输出报告路径 | 关闭 |
| `--json-only` | | 仅输出结构化 JSON，不调用 AI | 关闭 |
| `--verbose` | `-v` | 打印详细采集过程和各采集器耗时 | 关闭 |
| `--timeout` | | CDB 超时秒数 | 120 |
| `--no-cache` | | 跳过 CDB 缓存，强制重新运行 | 关闭 |
| `--clear-cache` | | 清空所有 CDB 缓存并退出 | — |

### AI 选项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--provider` | `deepseek` / `openai` / `anthropic` | `deepseek` |
| `--api-key` | API Key (或设环境变量) | 自动读环境变量 |
| `--model` | 模型名 (默认 provider 特定) | `deepseek-chat` / `gpt-4o` / `claude-sonnet-4-6` |

---

## 使用场景

### 场景一: 现场维护 — 快速诊断

```bash
# 客户现场崩溃，维护人员拿到 DMP 和软件目录
python -m mvp crash.dmp --exe-dir "D:\现场软件\MyApp" -v
```

**工作流**:
1. 工具自动采集 DMP 核心数据 (10-30秒)
2. AI 分析并给出根因 + 修复方向 (10-30秒)
3. 维护人员根据报告决定: 现场修复 or 升级上报

### 场景二: 开发者 — 源码级定位

```bash
python -m mvp crash.dmp \
    -e "C:\build\release" \
    -s "D:\git\myapp" \
    -p "D:\Symbols\v1.2.3" \
    --provider anthropic
```

**工作流**:
1. 工具自动匹配调用栈到源文件
2. 读取崩溃位置源码 + 近期 Git 变更
3. AI 基于源码给出具体修复代码

### 场景三: CI/CD 集成

```bash
# 自动化流水线 — JSON 输出 + 管道处理
python -m mvp crash.dmp --json-only -q > analysis.json
# 后续: 发到监控系统、生成 Jira Ticket、触发告警等
```

### 场景四: 批量分析

```bash
# 一次分析多个 DMP，自动聚类和分析模式
python -m mvp "C:\CrashDumps\*.dmp" --batch -e "C:\MyApp" -p "D:\Symbols"
```

**批量汇总报告包含**:
- **概览表**: 每个 DMP 一行（异常、模块、AI 根因摘要）
- **异常聚类**: 相同异常类型归组统计，快速识别高频问题
- **模块频率**: 哪些模块最常出现在崩溃中
- **时间线**: 按崩溃时间排序，发现时间规律
- **链接**: 可点击跳转到每个 DMP 的详细报告

### 场景五: PDB 不在 EXE 目录

```bash
python -m mvp crash.dmp -e "C:\MyApp" \
    -p "D:\Symbols\v1.2.3" \
    -p "\\server\pdbs\MyApp"
```

**效果对比**:

| 符号状态 | 调用栈质量 |
|---------|-----------|
| 无 PDB | `App+0x36cf` → 仅模块+偏移量 |
| 有 PDB | `App!TriggerNullPointerCrash+0x1f [process.cpp:342]` → 函数名+源文件行号 |

---

## 输出说明

### 报告章节

报告包含以下章节:

1. **🔍 崩溃摘要** — 异常类型/地址/时间/进程/PID
2. **🖥️ 崩溃机器系统信息** — CPU/内存/OS/系统运行时间/PID 内存使用 (从 DMP 提取)
3. **📚 崩溃调用栈** — 完整栈帧 (帧号/函数/源文件行号)
4. **📦 加载模块** — 所有模块及版本/大小/符号 (✅ 有符号 / ❌ 无符号)
5. **💻 崩溃位置源码** — 前后代码片段 (如果有 `--source-dir`)
6. **📝 日志错误摘要** — 崩溃窗口内的错误/警告
7. **⚙️ 应用配置** — 脱敏后的关键配置项
8. **🤖 AI 分析** — 根因分析/证据链/修复建议/置信度/预防措施

### HTML 输出 (`--format html`)

独立 HTML 文件，包含:
- 内嵌 CSS 样式，无需外部依赖
- 响应式布局 (max-width 900px)
- 代码高亮 (等宽字体 + 背景色)
- 表格带边框和表头底色
- 可直接在浏览器中打开，或嵌入 CI 报告

### JSON 输出 (`--json-only`)

```json
{
  "meta": {
    "dump_path": "crash.dmp",
    "exe_dir": "C:\\MyApp",
    "collected_at": "2026-06-28T01:37:54"
  },
  "dmp": {
    "system_info": {
      "os_name": "Windows 11",
      "os_version": "10.0.26100.1",
      "platform": "x64",
      "cpu_model": "Intel Core i7-13700",
      "cpu_count": 20,
      "total_physical_mb": 32768,
      "available_physical_mb": 2048,
      "system_uptime_seconds": 259200
    },
    "exception": {
      "code": "C0000005",
      "name": "ACCESS_VIOLATION",
      "address": "00007FF8ABCD1234",
      "type": "read",
      "attempted_address": "0000000000000000"
    },
    "crash_callstack": [
      {
        "frame_index": 0,
        "module": "mylib.dll",
        "function": "mylib!ProcessData+0x42",
        "source_file": "D:\\build\\src\\process.cpp",
        "source_line": 342
      }
    ],
    "modules": [...],
    "registers": {"rax": "0000000000000000", ...}
  },
  "binaries": {...},
  "source": {...},
  "logs": {...}
}
```

---

## AI 后端配置

### DeepSeek (默认)

```bash
# 设置 API Key (三选一)
set DEEPSEEK_API_KEY=sk-xxxxxxxxxxxxxxxx
# 或
python -m mvp crash.dmp --api-key sk-xxxxxxxxxxxxxxxx

# 使用
python -m mvp crash.dmp --provider deepseek
```

### OpenAI

```bash
set OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxx
python -m mvp crash.dmp --provider openai --model gpt-4o
```

### Anthropic (Claude)

```bash
set ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxx
python -m mvp crash.dmp --provider anthropic --model claude-sonnet-4-6
```

### 通用环境变量

```bash
set AI_API_KEY=sk-xxxxxxxxxxxxxxxx  # 所有 provider 的 fallback
```

---

## 高级功能

### 内存泄漏检测

工具自动从 DMP 中提取堆统计和虚拟地址空间数据，执行 9 项泄漏检测规则：

| # | 检测项 | 阈值 | 严重度 |
|---|--------|------|--------|
| 1 | 堆提交过大 | 平均 >100MB/堆 | HIGH |
| 2 | 保留/提交比异常 | reserved > 3× committed | HIGH |
| 3 | 虚拟地址耗尽 | 空闲 <100MB | HIGH |
| 4 | 进程提交超物理内存 | commit > RAM 80% | HIGH |
| 5 | 堆数量过多 | >20 个堆 | MEDIUM |
| 6 | LFH 未启用 | 大堆无 LFH | MEDIUM |
| 7 | 长时间运行 + 高提交 | 运行 >7天 + commit >500MB | HIGH |
| 8 | 堆损坏 | 检测到 corruption | HIGH |
| 9 | 高碎片率 | free/reserved >50% | MEDIUM |

**数据来源**: CDB 同时执行 `!heap -s` 和 `!address -summary`。即使 `!heap -s` 返回空（部分 DMP），`!address -summary` 始终可用。

**报告输出**: "内存/堆分析" 章节包含堆数量、提交/保留/空闲量、段数、LFH 状态、虚拟地址空闲量、检测到的问题列表（含证据和修复建议）。

### AI Prompt 专用模板

工具根据异常类型自动选择 6 种专用 Prompt 模板：

| 异常 | 模板 | 分析重点 |
|------|------|---------|
| ACCESS_VIOLATION | `access_violation.md` | 空指针/缓冲区溢出/use-after-free/栈损坏 |
| STATUS_NO_MEMORY / HEAP_CORRUPTION | `memory.md` | OOM/泄漏/碎片/commit charge |
| STACK_OVERFLOW | `stack_overflow.md` | 递归/大栈分配/死循环 |
| 除零错误 | `divide_by_zero.md` | 输入验证/未初始化变量 |
| CLR 异常 | `clr_exception.md` | 托管堆/GC/P/Invoke |
| 其他 | `generic.md` | 通用分析 |

模板自动降级：专用 → generic → 旧版 prompt_template.md。

### 批量关联分析 (`--batch --correlate`)

跨 DMP 挖掘共同模式，帮助解答：这些 DMP 是同一个 bug 吗？

```bash
python -m mvp crash1.dmp crash2.dmp --batch --correlate -e "C:\MyApp" -p "D:\Symbols"
```

**自动关联维度**（无需 AI）:
- **调用栈相似度**: 两两比对崩溃函数，输出相似度矩阵
- **系统状态共因**: 统计内存不足/长时间运行 DMP 占比
- **模块版本交叉比对**: 发现同一模块在不同 DMP 中的版本差异
- **崩溃频率趋势**: 分析崩溃间隔变化（加速恶化/稳定）
- **DMP 相似度排名**: 多维度综合排名

**限制**: 最多 **10 个 DMP**。

### 报告对比 (`--diff`)

对比两份已生成的报告，快速发现差异：

```bash
python -m mvp --diff report_v1.2.3.md report_v1.2.4.md
```

**对比维度**: 异常类型变化 / 调用栈差异 / 模块版本变化 / 系统环境变化

### PDF 导出 (`--format pdf`)

```bash
python -m mvp crash.dmp -e "C:\MyApp" --format pdf
```

**PDF 后端优先级**:
1. **Microsoft Edge** (headless) — Windows 自带，CJK 字体完美
2. **WeasyPrint** — 需 GTK/Pango
3. **fpdf2** — 纯 Python，基本支持

### CDB 输出缓存

工具自动缓存 CDB 分析输出（DMP → SHA256 前1MB），重复分析同一 DMP 时跳过 CDB 直接使用缓存。

- 缓存位置: `~/.dmp-analyzer/cache/`
- 上限: 200MB，LRU 自动淘汰
- `--no-cache` 跳过缓存
- `--clear-cache` 清空缓存

---

## 常见问题

### Q: 运行后显示 "CDB not found"

**A**: 需要安装 Windows SDK 调试工具。参见 [环境要求](#安装-windows-sdk-调试工具)。

或者手动指定 CDB 路径:
```bash
python -m mvp crash.dmp --cdb "D:\tools\cdb.exe"
```

### Q: CDB 分析超时 (timeout)

**A**: 增加超时时间:
```bash
python -m mvp crash.dmp --timeout 300
```

### Q: 符号显示为 ❌ (未加载)

**A**: 使用 `--symbol-path` / `-p` 指定 PDB 所在目录（可多次使用）:
```bash
python -m mvp crash.dmp -e "C:\MyApp" -p "D:\Symbols" -p "E:\Backup\pdbs"
```
EXE 目录自动作为首个搜索路径。工具不会主动连接微软符号服务器（大多数现场环境网络受限）。

### Q: 如何获得最佳符号加载效果？

**A**: 按优先级策略:
1. `--exe-dir` 指向 EXE 编译输出目录 (PDB 通常在旁边) — 自动加载
2. `-p` 添加额外 PDB 目录
3. 确保 PDB 与 DMP 中的模块时间戳匹配

工具在 CDB 分析后会扫描所有符号路径，检查是否存在匹配的 .pdb 文件。

### Q: AI 分析报错 "API key not found"

**A**: 检查环境变量是否设置:
```bash
echo %DEEPSEEK_API_KEY%
```
或通过参数传入:
```bash
python -m mvp crash.dmp --api-key sk-xxx
```

### Q: 报告中的中文显示为乱码

**A**: 设置控制台编码:
```bash
chcp 65001
python -m mvp crash.dmp
```
报告文件本身使用 UTF-8 编码，用任何 Markdown 阅读器打开均正常。

### Q: 日志采集找不到日志文件？

**A**: 工具会自动搜索以下位置:
- EXE 目录 + 父目录 (2 层)
- `%LOCALAPPDATA%` 和 `%TEMP%` 下的应用子目录
- 支持格式: `.log`, `.txt`, `.csv`, `.json`, `.etl`, `.trace`

也可手动指定:
```bash
python -m mvp crash.dmp --log-dir "C:\ProgramData\MyApp\logs"
```

### Q: 批量分析时如何自定义输出路径？

**A**:
```bash
python -m mvp *.dmp --batch --batch-output "weekly_crash_summary.md"
```

### Q: 可以在 Linux 上分析 Windows DMP 吗？

**A**: 当前 MVP 需要 Windows (因为 CDB.exe 只在 Windows 上运行)。
Phase 3 计划支持 Linux core dump 分析。

### Q: 分析结果准确吗？

**A**: AI 会给出置信度评分。High 置信度的结论通常可靠；Medium/Low 的需要人工验证。
**始终将 AI 分析作为辅助工具，关键决策需人工确认。**

---

## 附录

### A. 内部架构: 采集器流水线

```
用户输入 → 7 个采集器依次运行 → 填充 AnalysisContext → AI 推理 → 报告

采集器 (按顺序):
  1. DmpCollector      — 两遍 CDB (Pass1: ecxr+k+vertarget+analyze, Pass2: reload+lm+heap+locks)
  2. BinaryCollector   — PE 版本/哈希/多源搜索 (System32/SysWOW64)
  3. SymbolCollector   — PDB 匹配验证 (exe_dir + --symbol-path 所有路径)
  4. LogCollector      — 日志发现/时间窗口/错误提取 (9种时间戳格式)
  5. EventLogCollector — Windows Event Log (.evtx) 采集
  6. SourceCollector   — 源码匹配/Git 变更/工作区检查
  7. ConfigCollector   — 配置文件发现/脱敏
```

### B. CDB 两遍策略

**Pass 1** (快速): `.ecxr; k 30; ~* k; vertarget; !analyze -v`
→ 异常上下文、调用栈、系统信息、自动分析

**Pass 2** (补充): `.reload; lm; !heap -s; !locks`
→ 强制重载符号、模块列表、堆状态、锁检测

### C. 符号加载策略

```
优先级:
  1. --exe-dir            (自动作为首个搜索路径)
  2. --symbol-path / -p   (可多次指定，按顺序追加)
  
不连接: Microsoft Symbol Server (默认 _NT_SYMBOL_PATH="")

后处理: CDB 分析后扫描所有符号路径，检查匹配 .pdb 文件存在性
```

### D. 日志搜索策略

**搜索目录** (优先级顺序):
1. `--log-dir` (用户指定)
2. EXE 目录
3. EXE 父目录 (2 层上溯)
4. `%LOCALAPPDATA%\<AppName>`
5. `%TEMP%\<AppName>`

**支持格式**: `.log`, `.txt`, `.csv`, `.json`, `.etl`, `.trace`, `.dump`

**时间戳解析** (9 种格式):
- ISO 8601: `2026-06-28T01:37:54`
- CDB 格式: `Mon Jun 23 15:26:44.000 2026`
- 斜杠: `06/28/2026 01:37:54`
- 紧凑: `06-28 01:37:54`
- 中文: `2026年6月28日 01:37:54`
- Epoch: `1751343474`
- 空格: `2026-06-28 01:37:54`
- Windows 性能: `01:37:54.123`
- 12小时制: `01:37:54 PM`

**时间窗口**: 崩溃时间 ±5 分钟

### E. 异常码覆盖 (40+ 种)

| 类别 | 异常码示例 |
|------|-----------|
| 访问违例 | `C0000005` ACCESS_VIOLATION |
| 除零 | `C0000094` INTEGER_DIVIDE_BY_ZERO |
| 非法指令 | `C000001D` ILLEGAL_INSTRUCTION |
| 内存不足 | `C0000017` STATUS_NO_MEMORY |
| 栈溢出 | `C00000FD` STACK_OVERFLOW |
| 堆损坏 | `C0000374` HEAP_CORRUPTION |
| 断点 | `80000003` BREAKPOINT |
| 浮点异常 | `C000008F` FLOAT_INEXACT_RESULT |
| CLR/.NET | `E0434352` CLR_EXCEPTION |
| C++ 异常 | `E06D7363` CPP_EXCEPTION |
| 非法参数 | `C000000D` INVALID_PARAMETER |
| DLL 未找到 | `C0000135` DLL_NOT_FOUND |
| 管道断开 | `C00000B0` PIPE_NOT_CONNECTED |
| 更多... | 共 40+ 种异常码 |
