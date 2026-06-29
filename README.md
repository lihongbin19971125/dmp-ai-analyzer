# DMP AI Analyzer / DMP AI 分析器

> AI 驱动的 Windows 崩溃转储(.dmp)分析工具 — 拖入 DMP，秒出根因报告
> AI-powered Windows crash dump analysis — drop a `.dmp` file, get root cause analysis in seconds.

[![Rust](https://img.shields.io/badge/Rust-1.96%2B-orange)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-152%20passed-brightgreen)](https://github.com/lihongbin19971125/dmp-ai-analyzer/actions)
[![License](https://img.shields.io/badge/license-MIT-blue)](LICENSE)
[![Release](https://img.shields.io/badge/release-v1.0.0-blue)](https://github.com/lihongbin19971125/dmp-ai-analyzer/releases)

---

## 功能 (Features)

- **CDB 两遍分析** — 自动提取异常上下文、调用栈、模块、堆、锁
- **AI 根因推理** — DeepSeek / OpenAI / Claude 三后端 + 6 种专用 Prompt 模板
- **内存泄漏检测** — 9 项规则（高提交比、虚拟耗尽、堆损坏、碎片化等）
- **批量并行** — rayon 线程池，最多 10 个 DMP 同时分析
- **桌面应用** — Tauri v2 + React，拖拽 DMP，配置自动保存
- **多语言接口** — CLI exe、桌面 GUI、C FFI 动态库、PyO3 Python 模块

---

## 快速开始 (Quick Start)

### 桌面应用

从 [Releases](https://github.com/lihongbin19971125/dmp-ai-analyzer/releases) 下载 `dmp-tauri.exe`，双击运行。

### CLI 命令行

```bash
dmp analyze crash.dmp                                # 基本分析
dmp analyze crash.dmp -e "C:\MyApp" -p "D:\Symbols"   # 指定符号路径
dmp analyze *.dmp --batch --workers 4                 # 批量并行
dmp diff report1.md report2.md                        # 报告对比
```

### Rust 库

```rust
use dmp_core::*;
let result = analyze("crash.dmp", &AnalyzeOptions::default())?;
println!("{}", result.report_md);
```

### Python 绑定

```python
import _core
result = _core.analyze("crash.dmp", exe_dir="C:\\MyApp", json_only=True)
print(result.context_json)
```

---

## 环境要求 (Requirements)

| 组件 | 要求 |
|------|------|
| 操作系统 | Windows 10 / 11 |
| CDB 调试器 | Windows SDK Debugging Tools |
| Rust (开发) | 1.96+ MSVC |
| VS (开发) | 2019+ C++ 编译工具 |

---

## 从源码构建 (Building)

```bash
git clone https://github.com/lihongbin19971125/dmp-ai-analyzer.git
cd dmp-ai-analyzer

npm install                           # 前端依赖
cargo build --release -p dmp-cli     # 构建 CLI
cargo build --release -p dmp-ffi     # 构建 C FFI
cargo build --release -p dmp-py      # 构建 Python 模块
cargo tauri build                     # 构建桌面应用

cargo test --workspace                # 运行全部 152 测试
```

---

## 项目结构 (Structure)

```
dmp-ai-analyzer/
├── crates/                # Rust 工作区 (7 crates)
│   ├── dmp-context/       # 数据模型 (15 结构体)
│   ├── dmp-parser/        # CDB 输出解析 + 内存分析
│   ├── dmp-engine/        # CDB/AI/缓存/报告/模板/对比
│   ├── dmp-core/          # 公共 API + 批量编排
│   ├── dmp-ffi/           # C FFI 导出 (dmp_ffi.dll)
│   ├── dmp-py/            # PyO3 Python 绑定 (dmp_py.dll)
│   └── dmp-cli/           # CLI 工具 (dmp.exe)
├── src-tauri/             # Tauri 桌面应用后端
├── src/                   # React 前端
├── mvp/                   # Python MVP (保留)
└── docs/                  # 文档
```

---

## Feature 开关

| Feature | 所属 Crate | 说明 |
|---------|-----------|------|
| `http` | dmp-engine | AI API 调用 (reqwest + SChannel) |
| `parallel` | dmp-core | 并行 CDB 批量分析 (rayon) |

---

## 版本历史 (Releases)

| 版本 | 日期 | 说明 |
|------|------|------|
| [v1.0.0](https://github.com/lihongbin19971125/dmp-ai-analyzer/releases/tag/v1.0.0) | 2026-06-29 | 首个正式版：CLI + 桌面 UI + C FFI + PyO3 |

---

## License

MIT
