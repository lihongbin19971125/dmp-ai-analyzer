"""Memory leak detection from heap statistics and system state.

Analyzes DmpData (heap info, address summary, system memory) to detect
indicators of memory leaks, fragmentation, and resource exhaustion.
Works even when !heap -s returns empty by using !address -summary data.
"""

from .context import DmpData


class MemoryLeakAnalyzer:
    """Detect memory leak patterns from DMP heap and system data.

    Checks 9 indicators across heap state, virtual address space,
    physical memory, and system uptime correlation.
    """

    # Thresholds
    HIGH_COMMIT_PER_HEAP_MB = 100       # Per-heap average
    HIGH_RESERVED_RATIO = 3.0           # reserved / committed
    LOW_FREE_VIRTUAL_MB = 100           # Virtual address exhaustion
    HIGH_HEAP_COUNT = 20                # Too many heaps
    LONG_UPTIME_SECONDS = 86400 * 7     # 7 days
    HIGH_UPTIME_COMMIT_MB = 500
    HIGH_FRAGMENTATION_RATIO = 0.5      # free / reserved

    def __init__(self, dmp: DmpData):
        self.dmp = dmp
        self.heap = dmp.heap
        self.sys = dmp.system_info
        self.addr = dmp.address_summary

    def analyze(self) -> list[dict]:
        """Run all leak detection checks.

        Returns:
            List of finding dicts, each with:
            indicator, severity, evidence, recommendation.
            Empty list if no issues found.
        """
        findings = []

        checks = [
            self._check_high_commit,
            self._check_reserved_ratio,
            self._check_virtual_exhaustion,
            self._check_commit_vs_physical,
            self._check_heap_count,
            self._check_lfh_status,
            self._check_uptime_correlation,
            self._check_corruption,
            self._check_fragmentation,
        ]
        for check in checks:
            result = check()
            if result:
                findings.append(result)

        return findings

    # ── Rule 1: High commit ─────────────────────────────────

    def _check_high_commit(self) -> dict | None:
        avg = self.heap.total_committed_mb / max(self.heap.heap_count, 1)
        if avg > self.HIGH_COMMIT_PER_HEAP_MB:
            return {
                "indicator": "high_commit",
                "severity": "high",
                "evidence": f"堆平均提交 {avg:.0f}MB (阈值 {self.HIGH_COMMIT_PER_HEAP_MB}MB)",
                "recommendation": "检查是否存在内存泄漏，使用 !heap -s -v 查看每堆详情",
            }
        return None

    # ── Rule 2: Reserved vs committed ratio ─────────────────

    def _check_reserved_ratio(self) -> dict | None:
        if self.heap.total_committed_mb == 0:
            return None
        ratio = self.heap.total_reserved_mb / self.heap.total_committed_mb
        if ratio > self.HIGH_RESERVED_RATIO:
            return {
                "indicator": "high_reserved_ratio",
                "severity": "high",
                "evidence": f"保留/提交比 {ratio:.1f}:1 (阈值 {self.HIGH_RESERVED_RATIO}:1)",
                "recommendation": "高保留比表示堆碎片严重，考虑使用 LFH 或自定义分配器",
            }
        return None

    # ── Rule 3: Virtual address exhaustion ──────────────────

    def _check_virtual_exhaustion(self) -> dict | None:
        free_mb = self.addr.get("Free", 0)
        if 0 < free_mb < self.LOW_FREE_VIRTUAL_MB:
            return {
                "indicator": "virtual_exhaustion",
                "severity": "high",
                "evidence": f"虚拟地址空闲仅 {free_mb}MB (阈值 {self.LOW_FREE_VIRTUAL_MB}MB)",
                "recommendation": "虚拟地址接近耗尽，即使物理内存充足也会分配失败。检查虚拟内存碎片",
            }
        return None

    # ── Rule 4: Process commit vs physical RAM ──────────────

    def _check_commit_vs_physical(self) -> dict | None:
        total_commit = self.sys.process_working_set_mb + self.sys.process_pagefile_mb
        if total_commit > 0 and total_commit > self.sys.total_physical_mb * 0.8:
            return {
                "indicator": "commit_exceeds_ram",
                "severity": "high",
                "evidence": f"进程提交 {total_commit}MB > 物理内存 80% ({self.sys.total_physical_mb}MB)",
                "recommendation": "进程提交量已超过物理内存，可能触发页面文件交换导致性能下降和分配失败",
            }
        return None

    # ── Rule 5: Too many heaps ──────────────────────────────

    def _check_heap_count(self) -> dict | None:
        if self.heap.heap_count > self.HIGH_HEAP_COUNT:
            return {
                "indicator": "high_heap_count",
                "severity": "medium",
                "evidence": f"{self.heap.heap_count} 个堆 (阈值 {self.HIGH_HEAP_COUNT})",
                "recommendation": "大量堆可能由 DLL 各自创建堆导致。建议统一使用进程默认堆或合并分配策略",
            }
        return None

    # ── Rule 6: LFH not enabled on large heaps ──────────────

    def _check_lfh_status(self) -> dict | None:
        if not self.heap.lfh_enabled and self.heap.total_committed_mb > 50:
            return {
                "indicator": "lfh_disabled",
                "severity": "medium",
                "evidence": f"堆提交 {self.heap.total_committed_mb}MB 但 LFH 未启用",
                "recommendation": "启用低碎片堆 (LFH) 以减少内存碎片。调用 HeapSetInformation 设置 LFH",
            }
        return None

    # ── Rule 7: Long uptime + high commit → slow leak ───────

    def _check_uptime_correlation(self) -> dict | None:
        if (self.sys.system_uptime_seconds > self.LONG_UPTIME_SECONDS and
                self.heap.total_committed_mb > self.HIGH_UPTIME_COMMIT_MB):
            hours = self.sys.system_uptime_seconds // 3600
            return {
                "indicator": "uptime_leak_correlation",
                "severity": "high",
                "evidence": f"运行 {hours}h, 堆提交 {self.heap.total_committed_mb}MB",
                "recommendation": "长时间运行伴随高提交量 → 可能存在慢速内存泄漏。使用性能监视器跟踪进程内存趋势",
            }
        return None

    # ── Rule 8: Heap corruption ─────────────────────────────

    def _check_corruption(self) -> dict | None:
        if self.heap.corrupted:
            details = "; ".join(self.heap.details[:3]) if self.heap.details else "堆损坏检测阳性"
            return {
                "indicator": "heap_corruption",
                "severity": "high",
                "evidence": details[:200],
                "recommendation": "堆已损坏。可能是 use-after-free 或缓冲区溢出，使用 Application Verifier 进行详细检测",
            }
        return None

    # ── Rule 9: High fragmentation ──────────────────────────

    def _check_fragmentation(self) -> dict | None:
        if (self.heap.total_reserved_mb > 0 and
                self.heap.free_bytes > 0 and
                self.heap.free_bytes / (self.heap.total_reserved_mb * 1024 * 1024) >
                self.HIGH_FRAGMENTATION_RATIO):
            ratio = self.heap.free_bytes / (self.heap.total_reserved_mb * 1024 * 1024)
            return {
                "indicator": "high_fragmentation",
                "severity": "medium",
                "evidence": f"碎片率 {ratio:.0%} (free/reserved), "
                           f"空闲 {self.heap.free_bytes // 1024}KB",
                "recommendation": "高碎片率导致内存利用率低。考虑合并小分配、使用内存池或启用 LFH",
            }
        return None

    # ── Summary ─────────────────────────────────────────────

    def pressure_reason(self, findings: list[dict]) -> str:
        """Generate a concise memory pressure reason from findings."""
        if not findings:
            return ""
        high = [f for f in findings if f["severity"] == "high"]
        if high:
            return f"检测到 {len(high)} 个严重内存问题: " + \
                   "; ".join(f["indicator"] for f in high[:3])
        return f"检测到 {len(findings)} 个内存异常指标"
