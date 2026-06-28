# DMP AI Analyzer — 开发计划与进度

> 当前状态: Phase 5 完成 (Rust 核心引擎) | 124 tests (Rust) + 283 tests (Python) | 端到端验证通过
> 更新日期: 2026-06-28

---

## Phase 1: MVP ✅ 完成

| ID | 任务 | 状态 |
|----|------|:--:|
| P1-01 | 单元测试套件 | ✅ |
| P1-02 | 解析器完善 (全格式支持) | ✅ |
| P1-03 | AI 端到端验证 (DeepSeek/OpenAI/Claude) | ✅ |
| P1-04 | 符号路径增量加载 (`-p` 多次指定) | ✅ |
| P1-05 | 批量分析模式 (`--batch` + glob) | ✅ |
| P1-06 | 报告质量打磨 (✅❌/后缀/全量) | ✅ |
| P1-07 | 源码采集优化 (±5行/Git过滤) | ✅ |
| P1-08 | Binary Collector (PE版本/哈希/System32) | ✅ |
| P1-09 | Log Collector (30文件/499行/9种时间戳) | ✅ |
| P1-10 | CLI 体验打磨 (--quiet/--format/耗时) | ✅ |
| P1-11 | HTML 导出 (md_to_html/内嵌CSS) | ✅ |
| P1-12 | 异常分类增强 (22→40+) | ✅ |

## Phase 2: 质量与深度 ✅ 完成

| ID | 任务 | 状态 | 产出 |
|----|------|:--:|------|
| P2-01 | **PDF 报告导出** | ✅ | Edge → WeasyPrint → fpdf2 三级降级 |
| P2-02 | **多 DMP 关联分析** | ✅ | CorrelationAnalyzer (调用栈/状态/版本/频率/排名) |
| P2-03 | **CDB 输出缓存** | ✅ | SHA256 key + 200MB LRU |
| P2-04 | **报告对比模式** | ✅ | diff.py (异常/调用栈/模块/系统 四维对比) |

## Phase 3: 深度分析增强 ✅ 完成

| ID | 任务 | 状态 | 产出 |
|----|------|:--:|------|
| P3-01 | **内存泄漏检测** | ✅ | MemoryLeakAnalyzer (9项规则), HeapInfo增强, address_summary |
| P3-02 | **专用 Prompt 模板** | ✅ | 6 模板 (access_violation/memory/stack_overflow/div0/clr/generic) |
| P3-03 | **测试覆盖率提升** | ✅ | 233→283 tests (+50) |

## Phase 4: 性能优化 ✅ 完成

| ID | 任务 | 状态 | 产出 |
|----|------|:--:|------|
| P4-01 | **并行 CDB** | ✅ | ThreadPoolExecutor, collect_context/analyze_context 分离 |
| P4-02 | **CDB 输出缓存** | ✅ | DefaultHasher, 200MB LRU |

## Phase 5: Rust 核心引擎 ✅ 完成

| ID | 任务 | 状态 | 产出 |
|----|------|:--:|------|
| P5-01 | **Workspace 搭建** | ✅ | 6 crates: dmp-context, dmp-parser, dmp-engine, dmp-core, dmp-ffi, dmp-py |
| P5-02 | **数据模型** (dmp-context) | ✅ | 15 structs + Serialize/Deserialize, 8 tests |
| P5-03 | **CDB 解析器** (dmp-parser) | ✅ | 9 parse fns + MemoryLeakAnalyzer, 27 tests |
| P5-04 | **引擎核心** (dmp-engine) | ✅ | CDB/cache/AI/report/template/diff, 37 tests |
| P5-05 | **公共 API** (dmp-core) | ✅ | analyze() / analyze_batch(), 8 unit + 28 integration tests |
| P5-06 | **C FFI** (dmp-ffi) | ✅ | extern "C" dmp_analyze(), 3 tests |
| P5-07 | **PyO3 绑定** (dmp-py) | ✅ | Python analyze() + AnalyzeResult, 4 tests |
| P5-08 | **http feature** | ✅ | reqwest + native-tls (SChannel), DeepSeek/OpenAI/Anthropic |
| P5-09 | **parallel feature** | ✅ | rayon parallel CDB batch |
| P5-10 | **端到端集成测试** | ✅ | 真实 DMP + CDB 全流程验证, 9 e2e tests |
| P5-11 | **工具链切换** | ✅ | rust-toolchain.toml → MSVC (解决 dlltool/gcc 问题) |

### Rust 项目指标

| 维度 | 数值 |
|------|------|
| Crates | 6 (context / parser / engine / core / ffi / py) |
| Rust 源代码 | ~2,800 行 |
| Rust 测试 | **124 tests, 0 failures** |
| Cargo features | http (AI 调用), parallel (并行 CDB) |
| 外部依赖 | serde, regex, reqwest (optional), rayon (optional), pyo3 (dmp-py) |
| 工具链 | stable-x86_64-pc-windows-msvc (VS2019) |
| Python 绑定 | PyO3 0.23, Python 3.12 |

### Python MVP 指标 (保留)

| 维度 | 数值 |
|------|------|
| 源文件 | 23 个 .py + 6 模板 .md |
| 测试文件 | 15 个 |
| 源代码 | 5,809 行 |
| 测试代码 | 6,072 行 |
| Python 测试 | **283 passed** (2 skipped) |
| CLI 参数 | 24 个 |

---

## Phase 6: 跨平台 UI (规划中)

| ID | 任务 | 工时 | 优先级 | 说明 |
|----|------|------|--------|------|
| P6-01 | **Tauri 桌面应用** | 40h | 🔴 P0 | React + Tauri + dmp-core |
| P6-02 | **VSCode 扩展** | 16h | 🔴 P0 | 右键 .dmp → 分析，调用栈点击跳转源码 |
| P6-03 | **CLI 工具 (Rust)** | 8h | 🟡 P1 | `dmp analyze crash.dmp --exe-dir ...` |
| P6-04 | **驱动/内核 DMP** | 8h | 🟡 P1 | Kernel Memory Dump 支持 |
| P6-05 | **实时 DMP 监控** | 8h | 🟡 P1 | 监控目录自动分析新 DMP |
| P6-06 | **报告导出增强** | 4h | 🟢 P2 | 批量 PDF 合并、邮件发送 |

---

## 项目文件结构

```
d:\code\dmp\
├── Cargo.toml                         # Rust workspace 定义
├── rust-toolchain.toml                # 锁定 MSVC 工具链
├── crates/                            # Rust workspace (6 crates)
│   ├── dmp-context/src/lib.rs         # 数据模型 (15 structs)
│   ├── dmp-parser/src/lib.rs          # CDB 输出解析 + 内存分析
│   ├── dmp-engine/src/
│   │   ├── lib.rs                     # 模块重导出
│   │   ├── cdb.rs                     # CDB 调用封装
│   │   ├── ai.rs                      # AI 三后端 (http feature)
│   │   ├── cache.rs                   # LRU 缓存
│   │   ├── report.rs                  # Markdown 报告生成
│   │   ├── template.rs               # Prompt 模板选择
│   │   └── diff.rs                    # 报告对比
│   ├── dmp-core/src/lib.rs            # analyze() + analyze_batch()
│   │   └── tests/
│   │       ├── integration_tests.rs    # 28 跨模块集成测试
│   │       └── real_dmp_tests.rs      # 9 真实 DMP 端到端测试
│   ├── dmp-ffi/src/lib.rs             # C FFI (extern "C")
│   └── dmp-py/src/lib.rs              # PyO3 Python 绑定
├── mvp/                               # Python MVP (保留)
│   ├── cli.py                         # CLI 入口 (24 参数)
│   ├── context.py                     # 数据模型
│   ├── cdb_runner.py                  # CDB 调用
│   ├── parser.py                      # 输出解析
│   ├── ai_client.py                   # 三后端 AI
│   ├── reporter.py                    # Markdown/HTML/PDF
│   ├── batch.py                       # 批量 + 关联分析
│   ├── cache_manager.py               # CDB 缓存
│   ├── diff.py                        # 报告对比
│   ├── memory_analyzer.py             # 内存泄漏检测 (9 规则)
│   ├── template_selector.py           # Prompt 模板选择
│   └── collectors/                    # 7 采集器
├── tests/                             # Python 测试套件 (13 文件)
├── templates/                         # AI Prompt 模板 (6 .md)
├── docs/                              # 文档
│   ├── user-manual.md                 # 使用说明书
│   ├── backlog.md                     # 本文件
│   └── ui-architecture.md             # UI 架构
└── requirements.txt                   # Python 依赖
```
