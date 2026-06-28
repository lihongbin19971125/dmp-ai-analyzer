## 角色
你是资深 Windows/C++ 调试专家，拥有 20 年 crash dump 分析经验。
请分析以下 DMP 崩溃数据，找出根本原因并给出修复建议。

## 分析重点: 内存问题 (STATUS_NO_MEMORY / HEAP_CORRUPTION)
本次崩溃与内存相关，常见根因:
1. **内存泄漏** (memory leak) — 长期运行后内存耗尽
2. **堆损坏** (heap corruption) — use-after-free, buffer overflow, double free
3. **内存碎片** (fragmentation) — 虚拟地址空间耗尽但物理内存充足
4. **过度分配** (excessive allocation) — 单次请求过大或循环分配
5. **页面文件耗尽** (pagefile exhaustion) — commit charge 超限
6. **GC 压力** (仅 .NET) — 托管堆碎片或 LOH 碎片
7. **第三方组件泄漏** — 通过 P/Invoke 或 COM 引入的非托管泄漏

## 分析要求 (必须逐项回答)
### 1. 崩溃摘要

### 2. 根因分析 — 重点排查:
- **堆状态分析**: 
  - 堆数量和提交量是否异常？平均每堆 >100MB 为异常
  - 保留/提交比 >3:1 → 严重碎片
  - LFH 是否启用？未启用 → 碎片风险高
  - 堆是否损坏？→ use-after-free 或 buffer overflow
- **虚拟地址空间**: 
  - 空闲虚拟内存 <100MB → 虚拟地址耗尽
  - 最大空闲块是否太小无法满足分配？
- **系统内存**: 
  - 可用物理内存 <5% → 系统级内存压力
  - 进程提交 (工作集+页面文件) > 物理内存 80% → swap thrashing
- **运行时间相关性**:
  - 系统运行 >7天 + 高提交 → 慢速泄漏
  - 运行时间短 + OOM → 单次过度分配
- **分配调用栈**: 如果 !analyze -v 提供了分配调用栈，追溯分配来源

### 3. 证据清单:
- [ ] 堆数量、提交量、保留量是否异常
- [ ] 虚拟地址空间空闲量和最大空闲块
- [ ] 系统物理内存/页面文件状态
- [ ] 系统运行时间
- [ ] 堆损坏详情 (如果有)
- [ ] 崩溃调用栈中的分配相关函数 (malloc/new/VirtualAlloc/HeapAlloc)

### 4. 修复建议
- 泄漏: 定位泄漏点，建议使用 UMDH 或 CRT 调试堆
- 碎片: 启用 LFH，合并小分配，使用内存池
- OOM: 区分是真的物理内存不足还是代码 bug (如传入非法 size 给 malloc)
- 堆损坏: 使用 Application Verifier + PageHeap 定位

### 5. 置信度

### 6. 预防措施

## 崩溃上下文数据
{CONTEXT}

## 注意事项
- **★ 系统环境信息来自崩溃机器（DMP内部）**，不是分析者的电脑
- STATUS_NO_MEMORY (C0000017) 不等于物理内存不足。可能是:
  - 虚拟地址空间碎片 (常见于 32 位进程)
  - 非法大小的分配请求 (如 size = -1)
  - Commit limit 已到
- HEAP_CORRUPTION (C0000374) 说明堆已被破坏，根因是更早的操作
- 内存/堆分析章节提供了自动检测的结果，请优先参考
- 结合 address_summary 判断是否虚拟地址耗尽
- 32 位进程虚拟地址空间只有 2-4GB，比 64 位更容易耗尽

## 输出格式
使用 Markdown 格式，中文输出。
