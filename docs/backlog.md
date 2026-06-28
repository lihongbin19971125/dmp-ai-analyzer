# DMP AI Analyzer — 开发计划与进度

> 当前状态: Phase 2 完成 | 233 tests | 代码 ~10,600 行 (MVP 5,096 + 测试 5,517)
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

## 当前项目指标

| 维度 | 数值 |
|------|------|
| 源文件 | 20 个 .py (7 采集器 + 13 核心) |
| 测试文件 | 13 个 |
| 源代码 | 5,096 行 |
| 测试代码 | 5,517 行 |
| 测试通过 | 233 passed (2 skipped) |
| CLI 参数 | 24 个 |
| 报告格式 | Markdown + HTML + PDF |

## Phase 3: 深度分析增强 ✅ 完成

| ID | 任务 | 状态 | 产出 |
|----|------|:--:|------|
| P3-01 | **内存泄漏检测** | ✅ | MemoryLeakAnalyzer (9项规则), HeapInfo增强, address_summary, Reporter堆分析章节 |
| P3-02 | **专用 Prompt 模板** | ✅ | 6 模板 (access_violation/memory/stack_overflow/div0/clr/generic), template_selector |
| P3-03 | **测试覆盖率提升** | ✅ | 233→283 tests (+50), 核心模块 89-100% |

### 当前项目指标

| 维度 | 数值 |
|------|------|
| 源文件 | 23 个 .py + 6 模板 .md |
| 测试文件 | 15 个 |
| 源代码 | 5,809 行 |
| 测试代码 | 6,072 行 |
| 测试通过 | 283 passed (2 skipped) |
| CLI 参数 | 24 个 |
| 报告格式 | Markdown + HTML + PDF |
| 覆盖率 | 76% (核心 89-100%) |

## Phase 4: 下一步 (建议)

| ID | 任务 | 工时 | 优先级 | 说明 |
|----|------|------|--------|------|
| P4-01 | **VSCode 扩展** | 16h | 🔴 P0 | 右键 .dmp → 分析，调用栈点击跳转源码 |
| P4-02 | **驱动/内核 DMP** | 8h | 🔴 P0 | Kernel Memory Dump 支持 |
| P4-03 | **实时 DMP 监控** | 8h | 🟡 P1 | 监控目录自动分析新 DMP |
| P4-04 | **报告导出增强** | 4h | 🟡 P1 | 批量 PDF 合并、邮件发送 |
| P4-05 | **性能优化** | 6h | 🟡 P1 | 并行 CDB 调用、流式 AI 输出 |
| P4-06 | **Rust 核心引擎** | 40h | 🟢 P2 | `dmp-core` crate + C FFI |
| P4-07 | **Linux/macOS 支持** | 80h | 🟢 P2 | GDB/lldb 后端 |

## 项目文件结构

```
d:\code\dmp\
├── mvp/                              # 核心代码 (20 .py 文件)
│   ├── cli.py                        ✅ CLI 入口 (24 参数)
│   ├── context.py                    ✅ 数据模型
│   ├── cdb_runner.py                 ✅ CDB 调用
│   ├── parser.py                     ✅ 输出解析
│   ├── ai_client.py                  ✅ 三后端 AI
│   ├── reporter.py                   ✅ Markdown/HTML/PDF
│   ├── batch.py                      ✅ 批量 + 关联分析
│   ├── cache_manager.py              ✅ CDB 缓存
│   ├── diff.py                       ✅ 报告对比
│   ├── prompt_template.md            ✅ AI Prompt
│   └── collectors/                   ✅ 7 采集器
├── tests/                            # 测试套件 (13 文件)
│   ├── test_cache_manager.py         (19 tests)
│   ├── test_batch.py                 (27 tests)
│   ├── test_diff.py                  (10 tests)
│   ├── test_log_collector.py         (22 tests)
│   ├── test_binary_collector.py      (19 tests)
│   ├── test_reporter.py              (33 tests)
│   ├── test_parser.py                + others
│   └── ...
├── docs/                             # 文档
│   ├── user-manual.md                ✅ 使用说明书
│   ├── backlog.md                    ✅ 本文件
│   └── ui-architecture.md            ✅ UI 架构
└── requirements.txt                  ✅
```
