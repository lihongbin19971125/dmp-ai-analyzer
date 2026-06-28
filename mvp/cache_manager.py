"""CDB output cache with LRU eviction.

Stores CDB analysis output keyed by DMP file hash (SHA256 of first 1MB).
Supports per-pass storage (Pass 1 = crash analysis, Pass 2 = module listing).
Automatically evicts oldest entries when total cache exceeds max_size_mb.
"""

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional


class CacheManager:
    """Manages CDB output cache on disk with LRU eviction."""

    def __init__(self, cache_dir=None, max_size_mb: float = 200):
        self.cache_dir = Path(cache_dir) if cache_dir else (
            Path.home() / ".dmp-analyzer" / "cache"
        )
        self.max_size_mb = max_size_mb
        self.meta_path = self.cache_dir / "cache_meta.json"

    # ── Hash ─────────────────────────────────────────────────

    @staticmethod
    def compute_hash(dmp_path: str) -> str:
        """Compute SHA256 of the first 1MB of a DMP file.

        The first 1MB contains the DMP header and key structures,
        sufficient to uniquely identify a DMP file.

        Args:
            dmp_path: Path to the .dmp file.

        Returns:
            64-character hex digest string.

        Raises:
            FileNotFoundError: If the DMP file does not exist.
        """
        p = Path(dmp_path)
        if not p.is_file():
            raise FileNotFoundError(f"DMP file not found: {dmp_path}")
        hasher = hashlib.sha256()
        with open(p, "rb") as f:
            hasher.update(f.read(1_048_576))  # 1MB
        return hasher.hexdigest()

    # ── Cache file path ──────────────────────────────────────

    def _file_path(self, hash_key: str, pass_num: int = 1) -> Path:
        """Return the cache file path for a given hash and pass number.

        Uses sharded directories (first 2 chars of hash) to avoid
        too many files in a single directory.
        """
        subdir = self.cache_dir / hash_key[:2]
        return subdir / f"{hash_key}_pass{pass_num}.txt"

    # ── Metadata ─────────────────────────────────────────────

    def _load_meta(self) -> dict:
        """Load cache metadata, returning empty dict if missing or corrupt."""
        if not self.meta_path.is_file():
            return {}
        try:
            return json.loads(self.meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return {}

    def _save_meta(self, meta: dict):
        """Write cache metadata atomically."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = self.meta_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.meta_path)

    # ── Size helpers ─────────────────────────────────────────

    def _entry_size(self, hash_key: str, pass_num: int) -> int:
        """Return the size in bytes of a single cache entry."""
        fp = self._file_path(hash_key, pass_num)
        if fp.is_file():
            return fp.stat().st_size
        return 0

    def _total_cache_size(self) -> int:
        """Return total size of all cached files in bytes."""
        total = 0
        if self.cache_dir.is_dir():
            for root, _dirs, files in os.walk(self.cache_dir):
                for f in files:
                    if f != self.meta_path.name:
                        try:
                            total += (Path(root) / f).stat().st_size
                        except OSError:
                            pass
        return total

    # ── Put ──────────────────────────────────────────────────

    def put(self, hash_key: str, output: str, pass_num: int = 1):
        """Store CDB output in the cache.

        If the cache exceeds max_size_mb after writing, triggers LRU eviction.

        Args:
            hash_key: SHA256 hex digest from compute_hash().
            output: Raw CDB output text.
            pass_num: CDB pass number (1 = crash analysis, 2 = module listing).
        """
        # Ensure directory exists
        fp = self._file_path(hash_key, pass_num)
        fp.parent.mkdir(parents=True, exist_ok=True)

        # Write output
        fp.write_text(output, encoding="utf-8")

        # Update metadata
        meta = self._load_meta()
        now = time.time()
        if hash_key not in meta:
            meta[hash_key] = {
                "created_at": now,
                "last_access": now,
                "passes": [],
            }
        entry = meta[hash_key]
        entry["last_access"] = now
        if pass_num not in entry["passes"]:
            entry["passes"].append(pass_num)
        self._save_meta(meta)

        # Check size and evict if needed
        self._evict_if_needed()

    # ── Get ──────────────────────────────────────────────────

    def get(self, hash_key: str, pass_num: int = 1) -> Optional[str]:
        """Retrieve cached CDB output.

        Updates last_access timestamp on hit.

        Args:
            hash_key: SHA256 hex digest from compute_hash().
            pass_num: CDB pass number.

        Returns:
            Cached output text, or None if not found.
        """
        fp = self._file_path(hash_key, pass_num)
        if not fp.is_file():
            return None

        # Update access time in metadata
        meta = self._load_meta()
        if hash_key in meta:
            meta[hash_key]["last_access"] = time.time()
            self._save_meta(meta)

        return fp.read_text(encoding="utf-8")

    # ── Eviction ─────────────────────────────────────────────

    def _evict_if_needed(self):
        """Check cache size and evict LRU entries if over limit."""
        max_bytes = self.max_size_mb * 1_048_576
        current = self._total_cache_size()
        if current <= max_bytes:
            return

        meta = self._load_meta()
        # Sort entries by last_access (oldest first)
        sorted_hashes = sorted(
            meta.keys(),
            key=lambda h: meta[h].get("last_access", 0),
        )

        for h in sorted_hashes:
            if self._total_cache_size() <= max_bytes * 0.8:
                # Evicted enough to get below 80% capacity
                break
            # Remove all pass files for this hash
            for pn in meta[h].get("passes", [1]):
                fp = self._file_path(h, pn)
                try:
                    fp.unlink()
                except OSError:
                    pass
            del meta[h]

        self._save_meta(meta)

    # ── Clear ────────────────────────────────────────────────

    def clear(self):
        """Remove all cached files and metadata."""
        if self.cache_dir.is_dir():
            import shutil
            shutil.rmtree(self.cache_dir, ignore_errors=True)
