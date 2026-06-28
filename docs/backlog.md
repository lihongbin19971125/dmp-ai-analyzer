# DMP AI Analyzer — 开发计划与进度

> v1.0 发布 | 152 tests (Rust) + 283 tests (Python) | 端到端验证通过
> 更新日期: 2026-06-29

---

## 版本历史

### v1.0 (2026-06-29) — 首个完整发布

| 组件 | 说明 |
|------|------|
| **dmp.exe** (4.8 MB) | CLI 命令行工具，零依赖单文件 |
| **dmp-tauri.exe** (13 MB) | 桌面 UI 应用，React + Tauri |
| **dmp-core** crate | Rust 库，C FFI / PyO3 / Tauri 可嵌入 |
| **Python MVP** | 保留，283 tests，全功能 |

### v0.x 迭代记录

| 版本 | 日期 | 内容 |
|------|------|------|
| v0.3 | 06/28 | Rust CLI 工具 |
| v0.2 | 06/28 | Rust 核心引擎完成，端到端测试 |
| v0.1 | 06/28 | Python MVP 完成 |

---

## Phase 1-5: ✅ 全部完成

| Phase | 内容 | 状态 |
|-------|------|:--:|
| P1 | Python MVP (283 tests) | ✅ |
| P2 | 质量与深度 (PDF/关联/缓存/对比) | ✅ |
| P3 | 内存泄漏检测 + Prompt 模板 | ✅ |
| P4 | 性能优化 (并行 CDB) | ✅ |
| P5 | Rust 核心引擎 (6 crates, 152 tests) | ✅ |

---

## v1.0 Rust Workspace (8 crates)

| Crate | 类型 | 测试 | 说明 |
|-------|------|:--:|------|
| `dmp-context` | lib | 8 | 15 数据模型 structs |
| `dmp-parser` | lib | 27 | CDB 输出解析 + 内存分析 |
| `dmp-engine` | lib | 37 | CDB/AI/缓存/报告/模板/对比 |
| `dmp-core` | lib | 45 | 公共 API + 集成 + 端到端 |
| `dmp-ffi` | lib | 3 | C FFI 导出 |
| `dmp-py` | lib | 4 | PyO3 Python 绑定 |
| `dmp-cli` | bin | 20 | CLI 工具 (dmp.exe) |
| `dmp-tauri` | bin | 8 | Tauri 桌面应用 |
| **总计** | — | **152** | **0 failures** |

### Features

| Feature | Crate | 说明 |
|---------|-------|------|
| `http` | dmp-engine | AI API 调用 (reqwest + SChannel) |
| `parallel` | dmp-core | 并行 CDB (rayon) |

### 可嵌入接口

| 接口 | 语言 | 产物 |
|------|------|------|
| `dmp_core::analyze()` | Rust | dmp-core crate |
| `dmp_analyze()` | C/C++ | dmp-ffi.dll |
| `_core.analyze()` | Python | dmp-py (PyO3) |
| Tauri commands | JS/TS | dmp-tauri |

---

## Python MVP (保留)

| 维度 | 数值 |
|------|------|
| 源文件 | 23 .py + 6 模板 .md |
| 测试 | 283 passed (2 skipped) |
| 源码 | 5,809 行 |
| 测试代码 | 6,072 行 |

---

## Phase 6: v1.1 规划

| ID | 任务 | 工时 | 优先级 | 说明 |
|----|------|------|--------|------|
| P6-01 | **MSI 安装包** | 2h | 🔴 P0 | WiX Toolset 打包，一键安装 |
| P6-02 | **VSCode 扩展** | 16h | 🔴 P0 | 右键 .dmp → 分析，调用栈点击跳转源码 |
| P6-03 | **调用栈可视化** | 8h | 🟡 P1 | 图形化调用栈，可点击展开帧详情 |
| P6-04 | **分析历史** | 8h | 🟡 P1 | SQLite 存储历史分析记录，搜索/对比 |
| P6-05 | **批量报告导出** | 4h | 🟢 P2 | 批量 PDF 合并、邮件发送 |
| P6-06 | **驱动/内核 DMP** | 8h | 🟢 P2 | Kernel Memory Dump 支持 |

---

## 项目文件结构

```
d:\code\dmp\
├── Cargo.toml                    # Rust workspace (8 crates)
├── rust-toolchain.toml           # MSVC 工具链
├── crates/                       # Rust 核心
│   ├── dmp-context/              # 数据模型
│   ├── dmp-parser/               # CDB 解析器
│   ├── dmp-engine/               # 引擎核心
│   ├── dmp-core/                 # 公共 API
│   ├── dmp-ffi/                  # C FFI
│   ├── dmp-py/                   # PyO3 绑定
│   └── dmp-cli/                  # CLI 工具 (dmp.exe)
├── src-tauri/                    # Tauri 桌面应用
│   └── src/lib.rs                # Tauri commands
├── src/                          # React 前端
│   ├── App.tsx
│   └── components/
├── mvp/                          # Python MVP (保留)
├── tests/                        # Python 测试
├── docs/                         # 文档
│   ├── user-manual.md
│   ├── backlog.md
│   └── ui-architecture.md
└── dist/                         # Vite 构建输出
```
