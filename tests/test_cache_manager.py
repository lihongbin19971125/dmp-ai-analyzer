"""Tests for cache_manager.py — CDB output caching with LRU eviction."""

import hashlib
import json
import os
import time
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from mvp.cache_manager import CacheManager


# ── Fixtures ─────────────────────────────────────────────────

@pytest.fixture
def cache_dir(tmp_path):
    """Temporary cache directory."""
    return tmp_path / "cache"


@pytest.fixture
def cm(cache_dir):
    """Fresh CacheManager with small max size for testing."""
    return CacheManager(cache_dir=cache_dir, max_size_mb=1)


@pytest.fixture
def dummy_dmp(tmp_path):
    """Create a dummy DMP file for hash testing."""
    p = tmp_path / "test.dmp"
    # Write >1MB to test the "first 1MB" hash
    data = b"A" * 1_000_000 + b"B" * 500_000
    p.write_bytes(data)
    return p


# ── Hash computation ─────────────────────────────────────────

class TestHashComputation:
    """Tests for compute_hash() — SHA256 of first 1MB."""

    def test_small_file_hash(self, tmp_path):
        """Hash of a small file should match direct SHA256."""
        p = tmp_path / "small.dmp"
        p.write_bytes(b"hello world")
        cm = CacheManager(cache_dir=tmp_path / "cache")
        result = cm.compute_hash(str(p))
        expected = hashlib.sha256(b"hello world").hexdigest()
        assert result == expected

    def test_first_1mb_only(self, tmp_path):
        """Only first 1MB contributes to the hash."""
        p = tmp_path / "big.dmp"
        # First 1MB = A's, rest = B's
        data = b"A" * 1_048_576 + b"B" * 500_000
        p.write_bytes(data)
        cm = CacheManager(cache_dir=tmp_path / "cache")
        result = cm.compute_hash(str(p))
        expected = hashlib.sha256(b"A" * 1_048_576).hexdigest()
        assert result == expected

    def test_empty_file_hash(self, tmp_path):
        """Hash of empty file should still work."""
        p = tmp_path / "empty.dmp"
        p.write_bytes(b"")
        cm = CacheManager(cache_dir=tmp_path / "cache")
        result = cm.compute_hash(str(p))
        expected = hashlib.sha256(b"").hexdigest()
        assert result == expected

    def test_hash_consistency(self, dummy_dmp, cm):
        """Same file always produces same hash."""
        h1 = cm.compute_hash(str(dummy_dmp))
        h2 = cm.compute_hash(str(dummy_dmp))
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex digest

    def test_missing_file_raises(self, cm):
        """Non-existent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            cm.compute_hash("/nonexistent/file.dmp")


# ── Cache put/get ────────────────────────────────────────────

class TestCachePutGet:
    """Tests for put() and get() operations."""

    def test_put_and_get_basic(self, cm):
        """Put output, then get it back."""
        cm.put("abc123", "CDB output here", pass_num=1)
        result = cm.get("abc123", pass_num=1)
        assert result == "CDB output here"

    def test_get_miss_returns_none(self, cm):
        """Get with unknown hash returns None."""
        assert cm.get("nonexistent") is None

    def test_put_and_get_pass2(self, cm):
        """Different pass numbers store independently."""
        cm.put("abc123", "Pass 1 output", pass_num=1)
        cm.put("abc123", "Pass 2 output", pass_num=2)
        assert cm.get("abc123", pass_num=1) == "Pass 1 output"
        assert cm.get("abc123", pass_num=2) == "Pass 2 output"

    def test_put_overwrites_existing(self, cm):
        """Same hash+pass overwrites previous cache."""
        cm.put("abc123", "old output", pass_num=1)
        cm.put("abc123", "new output", pass_num=1)
        assert cm.get("abc123", pass_num=1) == "new output"

    def test_cache_file_location(self, cm):
        """Cache files are stored in sharded directories."""
        cm.put("a1b2c3d4e5f6", "output", pass_num=1)
        expected_dir = cm.cache_dir / "a1"
        expected_file = expected_dir / "a1b2c3d4e5f6_pass1.txt"
        assert expected_dir.exists()
        assert expected_file.exists()
        assert expected_file.read_text(encoding="utf-8") == "output"

    def test_meta_file_updated(self, cm):
        """Cache metadata is written after put."""
        cm.put("hash001", "some output", pass_num=1)
        assert cm.meta_path.exists()
        meta = json.loads(cm.meta_path.read_text())
        assert "hash001" in meta
        assert meta["hash001"]["passes"] == [1]

    def test_get_updates_access_time(self, cm):
        """get() should update last_access timestamp."""
        cm.put("hash002", "output", pass_num=1)
        time.sleep(0.01)
        cm.get("hash002", pass_num=1)
        meta = json.loads(cm.meta_path.read_text())
        # last_access should be newer than created_at
        assert meta["hash002"]["last_access"] >= meta["hash002"]["created_at"]


# ── LRU eviction ─────────────────────────────────────────────

class TestLRUEviction:
    """Tests for automatic LRU eviction when cache exceeds max size."""

    def test_eviction_triggered(self, cm):
        """When cache exceeds max, oldest entries are evicted."""
        # max_size_mb = 1 (1MB)
        # Write ~300KB entries — 4th should trigger eviction of oldest
        big_output = "X" * 300_000  # ~300KB
        cm.put("hash_A", big_output, pass_num=1)
        cm.put("hash_B", big_output, pass_num=1)
        cm.put("hash_C", big_output, pass_num=1)
        # Now ~900KB. 4th entry triggers eviction
        cm.put("hash_D", big_output, pass_num=1)

        # hash_A should be evicted (oldest)
        assert cm.get("hash_A") is None
        # hash_B might or might not be evicted (depends on exact timing)
        # hash_D should be present
        assert cm.get("hash_D") == big_output

    def test_recently_accessed_not_evicted(self, cm):
        """Recently accessed entries survive LRU eviction."""
        # 380KB each × 3 = 1140KB > 1MB limit → eviction on 3rd put
        big_output = "X" * 380_000
        cm.put("hash_A", big_output, pass_num=1)  # oldest
        cm.put("hash_B", big_output, pass_num=1)  # middle
        # Access hash_A to make it "recently used"
        cm.get("hash_A")
        time.sleep(0.05)
        # Now put hash_C — triggers eviction, should evict hash_B (not accessed)
        cm.put("hash_C", big_output, pass_num=1)
        # hash_A was recently accessed → should survive
        assert cm.get("hash_A") == big_output
        # hash_B was NOT accessed → should be evicted
        assert cm.get("hash_B") is None

    def test_eviction_respects_pass_files(self, cm):
        """When evicting, both pass1 and pass2 files are removed together."""
        big_output = "X" * 400_000
        cm.put("hash_A", big_output, pass_num=1)
        cm.put("hash_A", big_output, pass_num=2)
        cm.put("hash_B", big_output, pass_num=1)
        # Eviction should come
        cm.put("hash_C", big_output, pass_num=1)
        # hash_A pass1 and pass2 should both be gone
        assert cm.get("hash_A", pass_num=1) is None
        assert cm.get("hash_A", pass_num=2) is None


# ── Clear cache ──────────────────────────────────────────────

class TestClearCache:
    """Tests for clear() operation."""

    def test_clear_removes_all_files(self, cm):
        """clear() should remove all cached output and metadata."""
        cm.put("hash_X", "output X", pass_num=1)
        cm.put("hash_Y", "output Y", pass_num=1)
        cm.put("hash_Z", "output Z", pass_num=2)

        cm.clear()

        # All cache files gone
        assert not cm.cache_dir.exists() or not any(cm.cache_dir.iterdir())
        # Gets return None
        assert cm.get("hash_X") is None
        assert cm.get("hash_Y") is None
        assert cm.get("hash_Z", pass_num=2) is None

    def test_clear_can_reuse_cache(self, cm):
        """After clear, cache can be used again."""
        cm.put("hash_P", "first", pass_num=1)
        cm.clear()
        cm.put("hash_Q", "second", pass_num=1)
        assert cm.get("hash_Q") == "second"


# ── Cache directory creation ─────────────────────────────────

class TestCacheDir:
    """Tests for automatic cache directory creation."""

    def test_cache_dir_created_on_put(self, tmp_path):
        """Cache directory is created automatically on first put."""
        d = tmp_path / "nonexistent" / "cache"
        cm = CacheManager(cache_dir=d)
        assert not d.exists()
        cm.put("test", "output", pass_num=1)
        assert d.exists()

    def test_default_cache_dir(self):
        """Default cache directory is under user home."""
        cm = CacheManager()
        expected = Path.home() / ".dmp-analyzer" / "cache"
        assert cm.cache_dir == expected
