//! CDB output cache with hash keying and LRU eviction.
//! Ported from Python mvp/cache_manager.py.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct CacheManager {
    cache_dir: PathBuf,
    max_size_mb: f64,
    meta_path: PathBuf,
}

impl CacheManager {
    pub fn new(cache_dir: Option<PathBuf>, max_size_mb: f64) -> Self {
        let dir = cache_dir.unwrap_or_else(|| {
            dirs_cache().join(".dmp-analyzer").join("cache")
        });
        let meta = dir.join("cache_meta.json");
        Self { cache_dir: dir, max_size_mb, meta_path: meta }
    }

    /// Compute a hash from file path, size, and modification time.
    /// First 64KB of content is also hashed for uniqueness.
    pub fn compute_hash(&self, dmp_path: &Path) -> std::io::Result<String> {
        let meta = fs::metadata(dmp_path)?;
        let mut hasher = DefaultHasher::new();
        dmp_path.to_string_lossy().hash(&mut hasher);
        meta.len().hash(&mut hasher);
        meta.modified().ok().hash(&mut hasher);
        // Hash first 64KB of content
        if let Ok(mut file) = fs::File::open(dmp_path) {
            let mut buf = vec![0u8; 65536];
            if let Ok(n) = file.read(&mut buf) {
                buf[..n].hash(&mut hasher);
            }
        }
        Ok(format!("{:016x}", hasher.finish()))
    }

    fn file_path(&self, hash_key: &str, pass_num: u8) -> PathBuf {
        let subdir = self.cache_dir.join(&hash_key[..2]);
        subdir.join(format!("{}_pass{}.txt", hash_key, pass_num))
    }

    pub fn get(&self, hash_key: &str, pass_num: u8) -> Option<String> {
        let fp = self.file_path(hash_key, pass_num);
        if fp.is_file() {
            self.touch_meta(hash_key);
            fs::read_to_string(&fp).ok()
        } else {
            None
        }
    }

    pub fn put(&mut self, hash_key: &str, output: &str, pass_num: u8) -> std::io::Result<()> {
        let fp = self.file_path(hash_key, pass_num);
        if let Some(parent) = fp.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&fp, output)?;
        self.update_meta(hash_key, pass_num)?;
        self.evict_if_needed()
    }

    pub fn clear(&self) -> std::io::Result<()> {
        if self.cache_dir.is_dir() {
            fs::remove_dir_all(&self.cache_dir)?;
        }
        Ok(())
    }

    // ── Internal ──────────────────────────────────────────

    fn load_meta(&self) -> HashMap<String, serde_json::Value> {
        if self.meta_path.is_file() {
            fs::read_to_string(&self.meta_path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    fn save_meta(&self, meta: &HashMap<String, serde_json::Value>) -> std::io::Result<()> {
        if let Some(parent) = self.meta_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string(meta).unwrap_or_default();
        fs::write(&self.meta_path, json)
    }

    fn update_meta(&self, hash_key: &str, pass_num: u8) -> std::io::Result<()> {
        let mut meta = self.load_meta();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
        let entry = meta.entry(hash_key.to_string()).or_insert(serde_json::json!({
            "created_at": now,
            "last_access": now,
            "passes": [],
        }));
        entry["last_access"] = serde_json::json!(now);
        if let Some(passes) = entry["passes"].as_array_mut() {
            let pn = serde_json::json!(pass_num);
            if !passes.contains(&pn) {
                passes.push(pn);
            }
        }
        self.save_meta(&meta)
    }

    fn touch_meta(&self, hash_key: &str) {
        if let Ok(s) = fs::read_to_string(&self.meta_path) {
            if let Ok(mut meta) = serde_json::from_str::<HashMap<String, serde_json::Value>>(&s) {
                if let Some(entry) = meta.get_mut(hash_key) {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
                    entry["last_access"] = serde_json::json!(now);
                    let _ = self.save_meta(&meta);
                }
            }
        }
    }

    fn total_cache_size(&self) -> u64 {
        if !self.cache_dir.is_dir() {
            return 0;
        }
        let mut total = 0u64;
        if let Ok(entries) = fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                if let Ok(meta) = entry.metadata() {
                    if meta.is_file() {
                        total += meta.len();
                    }
                }
            }
        }
        total
    }

    fn evict_if_needed(&mut self) -> std::io::Result<()> {
        let max_bytes = (self.max_size_mb * 1_048_576.0) as u64;
        let current = self.total_cache_size();
        if current <= max_bytes {
            return Ok(());
        }
        let mut meta = self.load_meta();
        let mut entries: Vec<_> = meta.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        entries.sort_by(|a, b| {
            let ta = a.1["last_access"].as_f64().unwrap_or(0.0);
            let tb = b.1["last_access"].as_f64().unwrap_or(0.0);
            ta.partial_cmp(&tb).unwrap_or(std::cmp::Ordering::Equal)
        });
        for (h, v) in &entries {
            if self.total_cache_size() <= (max_bytes as f64 * 0.8) as u64 {
                break;
            }
            if let Some(passes) = v["passes"].as_array() {
                for pn in passes {
                    let fp = self.file_path(h, pn.as_u64().unwrap_or(1) as u8);
                    let _ = fs::remove_file(&fp);
                }
            }
            meta.remove(h);
        }
        self.save_meta(&meta)
    }
}

fn dirs_cache() -> PathBuf {
    // ~/.dmp-analyzer equivalent
    if cfg!(windows) {
        std::env::var("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("dmp-analyzer")
    } else {
        dirs_home().join(".dmp-analyzer")
    }
}

fn dirs_home() -> PathBuf {
    std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

// ═════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_cache(prefix: &str) -> CacheManager {
        let dir = std::env::temp_dir().join(prefix);
        let _ = std::fs::remove_dir_all(&dir); // clean from previous runs
        CacheManager::new(Some(dir), 10.0) // 10MB limit, won't evict in tests
    }

    #[test]
    fn test_compute_hash_small_file() {
        let cm = temp_cache("dmp_hash_test");
        let dmp = cm.cache_dir.parent().unwrap().join("test_hash.dmp");
        std::fs::write(&dmp, b"hello world").unwrap();
        let hash = cm.compute_hash(&dmp).unwrap();
        assert_eq!(hash.len(), 16);
    }

    #[test]
    fn test_put_and_get() {
        let mut cm = temp_cache("dmp_cache_putget");
        cm.put("abc123", "CDB output", 1).unwrap();
        assert_eq!(cm.get("abc123", 1), Some("CDB output".into()));
    }

    #[test]
    fn test_get_miss() {
        let cm = temp_cache("dmp_cache_miss");
        assert_eq!(cm.get("nonexistent", 1), None);
    }

    #[test]
    fn test_pass2_independent() {
        let mut cm = temp_cache("dmp_cache_pass2");
        cm.put("hash001", "pass1", 1).unwrap();
        cm.put("hash001", "pass2", 2).unwrap();
        assert_eq!(cm.get("hash001", 1), Some("pass1".into()));
        assert_eq!(cm.get("hash001", 2), Some("pass2".into()));
    }

    #[test]
    fn test_clear() {
        let mut cm = temp_cache("dmp_cache_clear");
        cm.put("hashX", "data", 1).unwrap();
        assert!(cm.get("hashX", 1).is_some());
        cm.clear().unwrap();
        assert!(cm.get("hashX", 1).is_none());
    }
}
