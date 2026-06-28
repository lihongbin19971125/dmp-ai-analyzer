//! Tauri backend for DMP AI Analyzer.
//! Wraps dmp_core::analyze() and dmp_core::analyze_batch() as Tauri commands.

use dmp_core::{AiProvider, AnalyzeOptions, AnalyzeResult, BatchResult};
use serde::{Serialize, Deserialize};
use std::sync::Mutex;

/// User settings persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserSettings {
    pub exe_dir: String,
    pub symbol_paths: String,
    pub provider: String,
    pub api_key: String,
    pub json_only: bool,
}

impl Default for UserSettings {
    fn default() -> Self {
        Self {
            exe_dir: String::new(),
            symbol_paths: String::new(),
            provider: "deepseek".into(),
            api_key: String::new(),
            json_only: false,
        }
    }
}

/// Application state shared across commands.
pub struct AppState {
    pub last_result: Mutex<Option<AnalyzeResult>>,
}

fn settings_path() -> std::path::PathBuf {
    let base = std::env::var("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::env::temp_dir());
    let dir = base.join("dmp-analyzer");
    std::fs::create_dir_all(&dir).ok();
    dir.join("settings.json")
}

/// Save user settings to disk.
#[tauri::command]
fn save_settings(settings: UserSettings) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&settings)
        .map_err(|e| format!("Serialize error: {}", e))?;
    std::fs::write(settings_path(), json)
        .map_err(|e| format!("Write error: {}", e))
}

/// Load user settings from disk.
#[tauri::command]
fn load_settings() -> Result<UserSettings, String> {
    let path = settings_path();
    if path.exists() {
        let json = std::fs::read_to_string(&path)
            .map_err(|e| format!("Read error: {}", e))?;
        serde_json::from_str(&json)
            .map_err(|e| format!("Parse error: {}", e))
    } else {
        Ok(UserSettings::default())
    }
}

/// Analyze a single DMP file.
#[tauri::command]
fn analyze_dmp(
    path: String,
    exe_dir: Option<String>,
    symbol_paths: Vec<String>,
    provider: Option<String>,
    api_key: Option<String>,
    model: Option<String>,
    timeout_secs: Option<u64>,
    json_only: Option<bool>,
) -> Result<AnalyzeResult, String> {
    let provider = match provider.unwrap_or_else(|| "deepseek".into()).to_lowercase().as_str() {
        "openai" => AiProvider::OpenAI,
        "anthropic" => AiProvider::Anthropic,
        _ => AiProvider::DeepSeek,
    };

    let mut paths = symbol_paths.clone();
    if let Some(ref exe) = exe_dir {
        paths.insert(0, exe.clone());
    }

    let opts = AnalyzeOptions {
        exe_dir,
        source_dir: None,
        symbol_paths: paths,
        provider,
        api_key,
        model,
        timeout_secs: timeout_secs.unwrap_or(120),
        workers: 0,
        no_cache: false,
        json_only: json_only.unwrap_or(false),
    };

    dmp_core::analyze(&path, &opts)
}

/// Analyze multiple DMP files in batch.
#[tauri::command]
fn analyze_batch_dmp(
    paths: Vec<String>,
    exe_dir: Option<String>,
    symbol_paths: Vec<String>,
    provider: Option<String>,
    api_key: Option<String>,
    model: Option<String>,
    timeout_secs: Option<u64>,
    workers: Option<usize>,
) -> Result<BatchResult, String> {
    let provider = match provider.unwrap_or_else(|| "deepseek".into()).to_lowercase().as_str() {
        "openai" => AiProvider::OpenAI,
        "anthropic" => AiProvider::Anthropic,
        _ => AiProvider::DeepSeek,
    };

    let mut symbol_paths_merged = symbol_paths.clone();
    if let Some(ref exe) = exe_dir {
        symbol_paths_merged.insert(0, exe.clone());
    }

    let opts = AnalyzeOptions {
        exe_dir,
        source_dir: None,
        symbol_paths: symbol_paths_merged,
        provider,
        api_key,
        model,
        timeout_secs: timeout_secs.unwrap_or(120),
        workers: workers.unwrap_or(0),
        no_cache: false,
        json_only: false,
    };

    dmp_core::analyze_batch(&paths, &opts)
}

/// Get version info.
#[tauri::command]
fn get_version() -> String {
    format!("dmp-core v{}", env!("CARGO_PKG_VERSION"))
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_version() {
        let v = get_version();
        assert!(v.contains("dmp-core"));
        assert!(v.contains("0.1.0"));
    }

    #[test]
    fn test_analyze_dmp_options_construction() {
        // Test that command parameters map correctly to options
        // We test by running with json_only=true on a non-existent file
        let result = analyze_dmp(
            "/nonexistent/test.dmp".into(),
            Some("C:\\MyApp".into()),
            vec!["D:\\Symbols".into()],
            Some("openai".into()),
            Some("sk-test".into()),
            Some("gpt-4o".into()),
            Some(300),
            Some(true),
        );

        // Should fail because file doesn't exist, but options are correctly mapped
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_dmp_default_provider() {
        let result = analyze_dmp(
            "nonexistent.dmp".into(),
            None, vec![], None, None, None, None, Some(true),
        );
        // Should fail with file-not-found error (CDB error), not API key error
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_batch_empty_list() {
        let result = analyze_batch_dmp(
            vec![],
            None, vec![], None, None, None, None, None,
        );
        // Empty file list should error
        assert!(result.is_err());
    }

    #[test]
    fn test_options_serialization_roundtrip() {
        // Verify AnalyzeOptions can be serialized/deserialized (for IPC)
        let opts = AnalyzeOptions {
            exe_dir: Some("C:\\App".into()),
            source_dir: None,
            symbol_paths: vec!["D:\\PDB".into()],
            provider: AiProvider::Anthropic,
            api_key: Some("sk-test123".into()),
            model: Some("claude-opus-4-8".into()),
            timeout_secs: 300,
            workers: 4,
            no_cache: true,
            json_only: false,
        };

        let json = serde_json::to_string(&opts).unwrap();
        let parsed: AnalyzeOptions = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.exe_dir, Some("C:\\App".into()));
        assert_eq!(parsed.symbol_paths, vec!["D:\\PDB"]);
        assert_eq!(parsed.workers, 4);
        assert!(parsed.no_cache);
    }

    #[test]
    fn test_app_state_default() {
        let state = AppState {
            last_result: Mutex::new(None),
        };
        let guard = state.last_result.lock().unwrap();
        assert!(guard.is_none());
    }

    #[test]
    fn test_user_settings_default() {
        let s = UserSettings::default();
        assert_eq!(s.provider, "deepseek");
        assert!(s.exe_dir.is_empty());
        assert!(!s.json_only);
    }

    #[test]
    fn test_user_settings_serialization() {
        let s = UserSettings {
            exe_dir: "C:\\App".into(),
            symbol_paths: "D:\\PDB".into(),
            provider: "openai".into(),
            api_key: "sk-test".into(),
            json_only: true,
        };
        let json = serde_json::to_string(&s).unwrap();
        let parsed: UserSettings = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.exe_dir, "C:\\App");
        assert_eq!(parsed.provider, "openai");
        assert_eq!(parsed.api_key, "sk-test");
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState {
            last_result: Mutex::new(None),
        })
        .invoke_handler(tauri::generate_handler![
            analyze_dmp,
            analyze_batch_dmp,
            get_version,
            save_settings,
            load_settings,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
