"""Tests for diff.py — report comparison mode."""

from pathlib import Path

import pytest

from mvp.diff import diff_reports, _parse_report_sections


# ── Helpers ─────────────────────────────────────────────────

def _write_report(path: Path, content: str):
    path.write_text(content, encoding="utf-8")


# ── Section parsing ─────────────────────────────────────────

class TestParseReportSections:
    """Tests for _parse_report_sections() — extracting sections from MD reports."""

    def test_extracts_exception_info(self):
        """Should extract exception code and name."""
        md = """# 崩溃分析报告
**DMP 文件**: `crash.dmp`
## 崩溃摘要
| 项目 | 值 |
|------|-----|
| 异常 | **ACCESS_VIOLATION** (`C0000005`) |
| 异常地址 | `00007FF8ABCD1234` |
"""
        sections = _parse_report_sections(md)
        assert sections["exception_code"] == "C0000005"
        assert sections["exception_name"] == "ACCESS_VIOLATION"

    def test_extracts_modules(self):
        """Should extract module names and versions."""
        md = """## 加载模块
| 模块 | 版本 | 基址 | 大小 | 符号 |
|------|------|------|------|------|
| myapp.exe | 1.2.3.0 | `00400000` | 2048 KB | ✅ |
| mylib.dll | 2.0.0.0 | `10000000` | 512 KB | ❌ |
"""
        sections = _parse_report_sections(md)
        assert len(sections["modules"]) == 2
        assert sections["modules"][0] == ("myapp.exe", "1.2.3.0")
        assert sections["modules"][1] == ("mylib.dll", "2.0.0.0")

    def test_extracts_system_info(self):
        """Should extract OS and memory info."""
        md = """## 崩溃机器系统信息
| 项目 | 值 |
|------|-----|
| 操作系统 | Windows 11 10.0.26200 (Build 26200) |
| CPU | Intel Core i7-13700 (20 核) |
| 物理内存 | 32768 MB 总量, 2048 MB 可用 (6%) |
"""
        sections = _parse_report_sections(md)
        assert "Windows 11" in sections["system_info"]
        assert "32768" in sections["system_info"]

    def test_extracts_callstack(self):
        """Should extract crash callstack functions."""
        md = """## 崩溃调用栈
```
   0  myapp!TriggerNullPointerCrash+0x1f  [process.cpp:342]
   1  myapp!WndProc+0x2b2  [main.cpp:156]
   2  user32!DispatchMessageW+0x3a
```
"""
        sections = _parse_report_sections(md)
        assert len(sections["callstack"]) >= 2
        assert any("TriggerNullPointerCrash" in f for f in sections["callstack"])

    def test_handles_empty_report(self):
        """Should handle empty/blank reports gracefully."""
        sections = _parse_report_sections("")
        assert sections["exception_code"] == "?"
        assert sections["modules"] == []


# ── Diff generation ─────────────────────────────────────────

class TestDiffReports:
    """Tests for diff_reports() — comparison of two reports."""

    def test_same_exception_different_module(self, tmp_path):
        """Two reports with same exception but different crashing module."""
        r1 = tmp_path / "r1.md"
        r2 = tmp_path / "r2.md"
        _write_report(r1, """# DMP 崩溃分析报告
## 崩溃摘要
| 异常 | **ACCESS_VIOLATION** (`C0000005`) |
## 崩溃调用栈
```
   0  myapp!ProcessData
```
## 加载模块
| myapp.exe | 1.0.0.0 |
""")
        _write_report(r2, """# DMP 崩溃分析报告
## 崩溃摘要
| 异常 | **ACCESS_VIOLATION** (`C0000005`) |
## 崩溃调用栈
```
   0  mylib!ReadBuffer
```
## 加载模块
| myapp.exe | 1.0.1.0 |
""")
        diff = diff_reports(str(r1), str(r2))
        # Same exception → 无变化 for exception type
        assert "无变化" in diff
        # But module version differs
        assert "1.0.0.0" in diff
        assert "1.0.1.0" in diff
        assert "C0000005" in diff

    def test_different_exception_types(self, tmp_path):
        """Two reports with different exception codes."""
        r1 = tmp_path / "r1.md"
        r2 = tmp_path / "r2.md"
        _write_report(r1, """# DMP 崩溃分析报告
## 崩溃摘要
| 异常 | **ACCESS_VIOLATION** (`C0000005`) |
""")
        _write_report(r2, """# DMP 崩溃分析报告
## 崩溃摘要
| 异常 | **STACK_OVERFLOW** (`C00000FD`) |
""")
        diff = diff_reports(str(r1), str(r2))
        assert "C0000005" in diff
        assert "C00000FD" in diff
        assert "异常类型变化" in diff

    def test_identical_reports(self, tmp_path):
        """Two identical reports should report no differences."""
        md = """# DMP 崩溃分析报告
## 崩溃摘要
| 异常 | **ACCESS_VIOLATION** (`C0000005`) |
"""
        r1 = tmp_path / "r1.md"
        r2 = tmp_path / "r2.md"
        _write_report(r1, md)
        _write_report(r2, md)
        diff = diff_reports(str(r1), str(r2))
        assert "无变化" in diff or "无显著差异" in diff

    def test_module_version_diff(self, tmp_path):
        """Should flag module version changes."""
        r1 = tmp_path / "r1.md"
        r2 = tmp_path / "r2.md"
        _write_report(r1, """# DMP 崩溃分析报告
## 加载模块
| mylib.dll | 1.0.0.0 |
| ntdll.dll | 10.0.26200 |
""")
        _write_report(r2, """# DMP 崩溃分析报告
## 加载模块
| mylib.dll | 2.0.0.0 |
| ntdll.dll | 10.0.26200 |
""")
        diff = diff_reports(str(r1), str(r2))
        assert "mylib.dll" in diff
        assert "1.0.0.0" in diff
        assert "2.0.0.0" in diff

    def test_missing_report_file_raises(self, tmp_path):
        """Should raise FileNotFoundError for missing report."""
        with pytest.raises(FileNotFoundError):
            diff_reports(str(tmp_path / "nope.md"), str(tmp_path / "also_nope.md"))
