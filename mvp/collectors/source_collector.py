"""Source code context collector.

When --source-dir is provided, matches callstack source file references
to actual source files, reads surrounding code, and checks git history.
"""

import os
import re
import subprocess
from pathlib import Path

from ..context import AnalysisContext, SourceCodeSnippet, SourceInfo
from .base import BaseCollector


class SourceCollector(BaseCollector):
    """Collect source code context around crash locations."""

    name = "source_collector"

    CONTEXT_LINES = 5  # lines before/after crash point to include

    def is_applicable(self, ctx: AnalysisContext) -> bool:
        return bool(ctx.source_dir) and Path(ctx.source_dir).is_dir()

    def collect(self, ctx: AnalysisContext) -> AnalysisContext:
        source_dir = Path(ctx.source_dir).resolve()
        info = SourceInfo()
        print(f"  [{self.name}] 搜索源码: {source_dir}")

        # Collect all source file references from callstacks
        source_refs: list[tuple[str, int]] = []  # (file_path, line)
        for frame in ctx.dmp.crash_callstack:
            if frame.source_file and frame.source_line:
                source_refs.append((frame.source_file, frame.source_line))

        seen_files = set()
        for file_path, line_num in source_refs:
            actual = self._find_source_file(file_path, source_dir)
            if actual and actual not in seen_files:
                seen_files.add(actual)
                snippet = self._read_source_context(actual, line_num)
                if snippet:
                    info.snippets.append(snippet)

        # Git info — filter to crash-related files only
        if self._is_git_repo(source_dir):
            print(f"  [{self.name}] 检测到 Git 仓库")
            crash_files = [s.file_path for s in info.snippets]
            info.recent_git_changes = self._get_recent_changes(source_dir, crash_files)
            info.working_tree_dirty = self._is_working_tree_dirty(source_dir)

        ctx.source = info
        print(f"  [{self.name}] 找到 {len(info.snippets)} 个源码片段, "
              f"{len(info.recent_git_changes)} 条近期修改")
        return ctx

    # ------------------------------------------------------------------

    def _find_source_file(self, dmp_path: str, source_dir: Path) -> Path | None:
        """Match a source file path from the DMP to a real file on disk.

        DMP paths are often absolute build-machine paths like
        ``D:\\build\\agent1\\src\\process.cpp`` — we need to find the corresponding
        file in the user's source tree.
        """
        filename = Path(dmp_path).name
        dmp_path_lower = dmp_path.lower().replace("\\", "/")

        # Strategy 1: Walk the tree looking for the filename, then pick
        # the best path match
        candidates: list[tuple[int, Path]] = []
        for root, dirs, files in os.walk(source_dir):
            # Skip .git, node_modules, etc.
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in
                       ("node_modules", "vendor", "__pycache__", "obj", "bin", ".vs")]
            if filename in files:
                candidate = Path(root) / filename
                rel = str(candidate.relative_to(source_dir)).lower().replace("\\", "/")
                # Score: more path segments match = better
                score = self._path_match_score(dmp_path_lower, rel)
                candidates.append((score, candidate))
            if len(candidates) > 5:  # don't over-search
                break

        if candidates:
            candidates.sort(key=lambda x: x[0], reverse=True)
            return candidates[0][1]

        return None

    def _path_match_score(self, dmp_path: str, candidate_rel: str) -> int:
        """Score how well a candidate path matches the DMP path."""
        score = 0
        dmp_parts = dmp_path.split("/")
        candidate_parts = candidate_rel.split("/")
        # Matching suffix segments
        for dp, cp in zip(reversed(dmp_parts), reversed(candidate_parts)):
            if dp == cp:
                score += 3
            elif dp.startswith(cp) or cp.startswith(dp):
                score += 1
        return score

    def _read_source_context(
        self, file_path: Path, crash_line: int
    ) -> SourceCodeSnippet | None:
        """Read source code around the crash line."""
        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").split("\n")
        except OSError:
            return None

        total = len(lines)
        start = max(0, crash_line - self.CONTEXT_LINES - 1)
        end = min(total, crash_line + self.CONTEXT_LINES)
        code_lines = lines[start:end]

        # Add line number annotations
        annotated = []
        for i, line in enumerate(code_lines, start=start + 1):
            marker = ">>>" if i == crash_line else "   "
            annotated.append(f"{marker} {i:6d} | {line}")

        return SourceCodeSnippet(
            file_path=str(file_path),
            crash_line=crash_line,
            start_line=start + 1,
            end_line=end,
            code="\n".join(annotated),
        )

    # ------------------------------------------------------------------
    # Git helpers
    # ------------------------------------------------------------------

    def _is_git_repo(self, path: Path) -> bool:
        return (path / ".git").is_dir()

    def _get_recent_changes(self, repo: Path, crash_files: list[str] | None = None) -> list[str]:
        """Get recent git log, filtered to crash-related files if available.

        Args:
            repo: Path to the git repository.
            crash_files: List of crash-related file paths to filter on.
        """
        try:
            # Build the command: git log -5, optionally filtered by file paths
            cmd = ["git", "-C", str(repo), "log", "--oneline", "-5",
                   "--format=%h %s (%ar by %an)"]

            # If we have crash files, filter to only those files
            # Use relative paths from the repo root
            if crash_files:
                for f in crash_files:
                    try:
                        rel = str(Path(f).relative_to(repo))
                        cmd.append("--")
                        cmd.append(rel)
                    except ValueError:
                        pass  # file not under repo, skip

            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                lines = [l.strip() for l in result.stdout.split("\n") if l.strip()]
                return lines[:5]  # keep max 5 entries
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            pass
        return []

    def _is_working_tree_dirty(self, repo: Path) -> bool:
        """Check if the working tree has uncommitted changes."""
        try:
            result = subprocess.run(
                ["git", "-C", str(repo), "status", "--porcelain"],
                capture_output=True, text=True, timeout=10
            )
            if result.returncode == 0:
                return bool(result.stdout.strip())
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            pass
        return False
