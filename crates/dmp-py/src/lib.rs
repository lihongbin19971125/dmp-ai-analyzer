//! PyO3 Python bindings for dmp-core.
//!
//! ```python
//! import dmp_core
//! result = dmp_core.analyze("crash.dmp", exe_dir="C:\\MyApp")
//! print(result.report_md)
//! ```

use pyo3::prelude::*;
use std::collections::HashMap;
use ::dmp_core::{AnalyzeOptions, AiProvider, analyze as core_analyze};

/// Python-visible result of DMP analysis.
#[pyclass]
#[derive(Clone)]
pub struct AnalyzeResult {
    #[pyo3(get)]
    pub context_json: String,
    #[pyo3(get)]
    pub ai_analysis: String,
    #[pyo3(get)]
    pub report_md: String,
    #[pyo3(get)]
    pub report_html: String,
    #[pyo3(get)]
    pub success: bool,
    #[pyo3(get)]
    pub error: Option<String>,
}

#[pymethods]
impl AnalyzeResult {
    fn __repr__(&self) -> String {
        if self.success {
            format!("AnalyzeResult(success=True, report_len={}, ai_len={})",
                self.report_md.len(), self.ai_analysis.len())
        } else {
            format!("AnalyzeResult(success=False, error={:?})", self.error)
        }
    }

    fn to_dict(&self) -> HashMap<String, String> {
        let mut d = HashMap::new();
        d.insert("context_json".into(), self.context_json.clone());
        d.insert("ai_analysis".into(), self.ai_analysis.clone());
        d.insert("report_md".into(), self.report_md.clone());
        d.insert("report_html".into(), self.report_html.clone());
        d.insert("success".into(), self.success.to_string());
        if let Some(ref e) = self.error {
            d.insert("error".into(), e.clone());
        }
        d
    }
}

/// Analyze a Windows crash dump file using CDB + AI.
///
/// Args:
///     dump_path: Path to the .dmp file.
///     exe_dir: Directory of the crashed executable (for symbols).
///     source_dir: Source code directory (for source-level resolution).
///     symbol_paths: Additional symbol server paths.
///     provider: AI provider — "deepseek" (default), "openai", or "anthropic".
///     api_key: API key override (or set env var).
///     model: Model override (or use provider default).
///     timeout_secs: CDB timeout in seconds (default 120).
///     workers: Number of parallel workers for batch analysis.
///     no_cache: Disable CDB output cache.
///     json_only: Skip AI analysis, return context JSON only.
#[pyfunction]
#[pyo3(signature = (
    dump_path,
    exe_dir = None,
    source_dir = None,
    symbol_paths = vec![],
    provider = "deepseek",  // &str in Rust signature
    api_key = None,
    model = None,
    timeout_secs = 120,
    workers = 0,
    no_cache = false,
    json_only = false,
))]
fn analyze(
    dump_path: String,
    exe_dir: Option<String>,
    source_dir: Option<String>,
    symbol_paths: Vec<String>,
    provider: &str,
    api_key: Option<String>,
    model: Option<String>,
    timeout_secs: u64,
    workers: usize,
    no_cache: bool,
    json_only: bool,
) -> AnalyzeResult {
    let provider_enum = match provider.to_lowercase().as_str() {
        "openai" => AiProvider::OpenAI,
        "anthropic" => AiProvider::Anthropic,
        _ => AiProvider::DeepSeek,
    };
    let opts = AnalyzeOptions {
        exe_dir,
        source_dir,
        symbol_paths,
        provider: provider_enum,
        api_key,
        model,
        timeout_secs,
        workers,
        no_cache,
        json_only,
    };

    match core_analyze(&dump_path, &opts) {
        Ok(r) => AnalyzeResult {
            context_json: r.context_json,
            ai_analysis: r.ai_analysis,
            report_md: r.report_md,
            report_html: r.report_html,
            success: true,
            error: None,
        },
        Err(e) => AnalyzeResult {
            context_json: String::new(),
            ai_analysis: String::new(),
            report_md: String::new(),
            report_html: String::new(),
            success: false,
            error: Some(e),
        },
    }
}

#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AnalyzeResult>()?;
    m.add_function(wrap_pyfunction!(analyze, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_result_success() {
        let r = AnalyzeResult {
            context_json: r#"{"test":1}"#.into(),
            ai_analysis: "AI result".into(),
            report_md: "# Report".into(),
            report_html: "<h1>Report</h1>".into(),
            success: true,
            error: None,
        };

        assert!(r.success);
        assert!(r.error.is_none());
        assert_eq!(r.context_json, r#"{"test":1}"#);
        assert!(r.ai_analysis.contains("AI"));
        assert!(r.report_md.starts_with("#"));

        let repr = r.__repr__();
        assert!(repr.contains("success=True"));

        let d = r.to_dict();
        assert_eq!(d.get("success").map(|s| s.as_str()), Some("true"));
        assert!(d.contains_key("context_json"));
    }

    #[test]
    fn test_analyze_result_error() {
        let r = AnalyzeResult {
            context_json: String::new(),
            ai_analysis: String::new(),
            report_md: String::new(),
            report_html: String::new(),
            success: false,
            error: Some("CDB not found".into()),
        };

        assert!(!r.success);
        assert_eq!(r.error, Some("CDB not found".into()));
        assert!(r.context_json.is_empty());

        let repr = r.__repr__();
        assert!(repr.contains("success=False"));
        assert!(repr.contains("CDB not found"));

        let d = r.to_dict();
        assert_eq!(d.get("error").map(|s| s.as_str()), Some("CDB not found"));
    }

    #[test]
    fn test_analyze_result_clone() {
        let r1 = AnalyzeResult {
            context_json: "data".into(),
            ai_analysis: "ai".into(),
            report_md: "md".into(),
            report_html: "html".into(),
            success: true,
            error: None,
        };
        let r2 = r1.clone();
        assert_eq!(r2.success, r1.success);
        assert_eq!(r2.context_json, r1.context_json);
    }

    #[test]
    fn test_analyze_nonexistent_dmp() {
        // analyze() should return an error for a non-existent file
        let result = analyze(
            "nonexistent_file.dmp".into(),
            None, None, vec![], "deepseek",
            None, None, 10, 0, true, true,
        );

        assert!(!result.success);
        assert!(result.error.is_some());
        let err = result.error.unwrap();
        // Error should mention the file or CDB issue
        assert!(!err.is_empty());
    }
}
