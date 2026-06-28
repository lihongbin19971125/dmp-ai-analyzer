"""Tests for memory_analyzer.py — MemoryLeakAnalyzer leak detection."""

import pytest
from mvp.context import DmpData, HeapInfo, SystemInfo
from mvp.memory_analyzer import MemoryLeakAnalyzer


def _make_dmp(
    heap_committed: int = 0,
    heap_reserved: int = 0,
    heap_count: int = 3,
    free_bytes: int = 0,
    segment_count: int = 1,
    lfh_enabled: bool = True,
    corrupted: bool = False,
    total_physical: int = 16384,
    available_physical: int = 8192,
    process_ws: int = 128,
    process_pagefile: int = 256,
    uptime: int = 3600,
    free_virtual: int = 100_000,
    per_heap: list | None = None,
) -> DmpData:
    """Build DmpData with controlled memory/heap state."""
    dmp = DmpData()
    dmp.heap = HeapInfo(
        total_committed_mb=heap_committed,
        total_reserved_mb=heap_reserved,
        heap_count=heap_count,
        free_bytes=free_bytes,
        segment_count=segment_count,
        lfh_enabled=lfh_enabled,
        corrupted=corrupted,
        per_heap_breakdown=per_heap or [],
    )
    dmp.system_info = SystemInfo(
        total_physical_mb=total_physical,
        available_physical_mb=available_physical,
        process_working_set_mb=process_ws,
        process_pagefile_mb=process_pagefile,
        system_uptime_seconds=uptime,
    )
    dmp.address_summary = {"Free": free_virtual, "Heap": heap_committed}
    return dmp


class TestHighCommit:
    """Rule 1:堆提交过大."""

    def test_flags_high_commit(self):
        dmp = _make_dmp(heap_committed=600, heap_count=5)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert any("commit" in f["indicator"].lower() for f in findings)

    def test_ignores_normal_commit(self):
        dmp = _make_dmp(heap_committed=50, heap_count=5)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert not any("commit" in f["indicator"].lower() for f in findings)


class TestReservedRatio:
    """Rule 2:保留/提交比异常."""

    def test_flags_high_reserved_ratio(self):
        dmp = _make_dmp(heap_committed=200, heap_reserved=1000)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert any("reserved" in f["indicator"].lower() or "frag" in f["indicator"].lower()
                   for f in findings)

    def test_ignores_normal_ratio(self):
        dmp = _make_dmp(heap_committed=200, heap_reserved=300)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert not any("reserved" in f["indicator"].lower() or "frag" in f["indicator"].lower()
                       for f in findings)


class TestVirtualExhaustion:
    """Rule 3:虚拟地址耗尽."""

    def test_flags_low_free_virtual(self):
        dmp = _make_dmp(free_virtual=50)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert any("virtual" in f["indicator"].lower() for f in findings)

    def test_ignores_normal_free(self):
        dmp = _make_dmp(free_virtual=200_000)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert not any("virtual" in f["indicator"].lower() for f in findings)


class TestCommitVsPhysical:
    """Rule 4:进程提交超物理内存."""

    def test_flags_commit_exceeds_ram(self):
        dmp = _make_dmp(
            total_physical=8192, available_physical=512,
            process_ws=4000, process_pagefile=5000)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert any("physical" in f["indicator"].lower() or "ram" in f["indicator"].lower()
                   for f in findings)

    def test_ignores_when_ram_plenty(self):
        dmp = _make_dmp(
            total_physical=32768, available_physical=16384,
            process_ws=500, process_pagefile=600)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert not any("physical" in f["indicator"].lower() or "ram" in f["indicator"].lower()
                       for f in findings)


class TestHeapCount:
    """Rule 5:堆数量过多."""

    def test_flags_many_small_heaps(self):
        dmp = _make_dmp(heap_count=30)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert any("heap_count" in f["indicator"].lower() or
                   "heap" in f["indicator"].lower() for f in findings)

    def test_ignores_few_heaps(self):
        dmp = _make_dmp(heap_count=10)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert not any("heap_count" in f["indicator"].lower() for f in findings)


class TestLFHStatus:
    """Rule 6:LFH 未启用."""

    def test_flags_lfh_disabled_on_large_heap(self):
        dmp = _make_dmp(lfh_enabled=False, heap_committed=500)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert any("lfh" in f["indicator"].lower() for f in findings)

    def test_ignores_lfh_disabled_on_small_heap(self):
        dmp = _make_dmp(lfh_enabled=False, heap_committed=20)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert not any("lfh" in f["indicator"].lower() for f in findings)


class TestUptimeCorrelation:
    """Rule 7:长时间运行 + 高提交."""

    def test_flags_long_uptime_high_commit(self):
        dmp = _make_dmp(uptime=86400 * 10, heap_committed=600, total_physical=8192)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert any("uptime" in f["indicator"].lower() or "运行" in f["indicator"]
                   for f in findings)

    def test_ignores_short_uptime(self):
        dmp = _make_dmp(uptime=3600, heap_committed=600)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert not any("uptime" in f["indicator"].lower() for f in findings)


class TestHeapCorruption:
    """Rule 8:堆损坏."""

    def test_flags_corruption(self):
        dmp = _make_dmp(corrupted=True, heap_committed=200)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert any("corrupt" in f["indicator"].lower() for f in findings)

    def test_ignores_no_corruption(self):
        dmp = _make_dmp(corrupted=False, heap_committed=200)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert not any("corrupt" in f["indicator"].lower() for f in findings)


class TestFragmentation:
    """Rule 9:高碎片率."""

    def test_flags_high_fragmentation(self):
        dmp = _make_dmp(
            heap_reserved=1000, free_bytes=600_000_000, heap_committed=600)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert any("frag" in f["indicator"].lower() for f in findings)

    def test_ignores_low_fragmentation(self):
        dmp = _make_dmp(
            heap_reserved=500, free_bytes=10_000_000, heap_committed=400)
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert not any("frag" in f["indicator"].lower() for f in findings)


class TestAnalyzeComprehensive:
    """Integration: multiple findings at once."""

    def test_multiple_indicators(self):
        dmp = _make_dmp(
            heap_committed=800, heap_reserved=3000, heap_count=25,
            lfh_enabled=False, corrupted=True,
            total_physical=4096, available_physical=200,
            process_ws=2000, process_pagefile=2500,
            uptime=86400 * 14, free_virtual=30, free_bytes=500_000_000,
        )
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert len(findings) >= 4  # Should flag many issues
        # Severities should be present
        for f in findings:
            assert "severity" in f
            assert f["severity"] in ("high", "medium", "low")
            assert "evidence" in f
            assert "recommendation" in f

    def test_healthy_system(self):
        dmp = _make_dmp(
            heap_committed=50, heap_reserved=80, heap_count=2,
            lfh_enabled=True, corrupted=False,
            total_physical=32768, available_physical=16384,
            process_ws=128, process_pagefile=200,
            uptime=3600, free_virtual=10_000_000,
        )
        analyzer = MemoryLeakAnalyzer(dmp)
        findings = analyzer.analyze()
        assert len(findings) == 0  # Completely healthy
