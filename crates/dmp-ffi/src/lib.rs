//! C FFI exports for dmp-core.
//!
//! Provides a C-compatible API for embedding in C/C++/C#/Java/etc.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

/// Result of DMP analysis (C-compatible).
#[repr(C)]
pub struct DmpResult {
    pub context_json: *mut c_char,
    pub ai_analysis: *mut c_char,
    pub report_md: *mut c_char,
    pub error: *mut c_char,
}

/// Analyze a DMP file.
///
/// # Safety
/// Caller must free the result with `dmp_result_free()`.
#[no_mangle]
pub unsafe extern "C" fn dmp_analyze(
    dump_path: *const c_char,
) -> DmpResult {
    let path = if dump_path.is_null() {
        return DmpResult::error("dump_path is null");
    } else {
        unsafe { CStr::from_ptr(dump_path) }.to_string_lossy().to_string()
    };

    let opts = dmp_core::AnalyzeOptions::default();
    match dmp_core::analyze(&path, &opts) {
        Ok(result) => DmpResult::ok(
            &result.context_json,
            &result.ai_analysis,
            &result.report_md,
        ),
        Err(e) => DmpResult::error(&e),
    }
}

/// Free a DmpResult.
///
/// # Safety
/// Must only be called once per result.
#[no_mangle]
pub unsafe extern "C" fn dmp_result_free(result: *mut DmpResult) {
    if result.is_null() {
        return;
    }
    unsafe {
        let r = &mut *result;
        if !r.context_json.is_null() { let _ = CString::from_raw(r.context_json); }
        if !r.ai_analysis.is_null() { let _ = CString::from_raw(r.ai_analysis); }
        if !r.report_md.is_null() { let _ = CString::from_raw(r.report_md); }
        if !r.error.is_null() { let _ = CString::from_raw(r.error); }
    }
}

impl DmpResult {
    fn ok(json: &str, ai: &str, report: &str) -> Self {
        DmpResult {
            context_json: CString::new(json).unwrap_or_default().into_raw(),
            ai_analysis: CString::new(ai).unwrap_or_default().into_raw(),
            report_md: CString::new(report).unwrap_or_default().into_raw(),
            error: std::ptr::null_mut(),
        }
    }

    fn error(msg: &str) -> Self {
        DmpResult {
            context_json: std::ptr::null_mut(),
            ai_analysis: std::ptr::null_mut(),
            report_md: std::ptr::null_mut(),
            error: CString::new(msg).unwrap_or_default().into_raw(),
        }
    }
}

// ═════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_result_ok() {
        let r = DmpResult::ok(r#"{"test":1}"#, "AI result", "Report");
        assert!(!r.context_json.is_null());
        assert!(r.error.is_null());
        let json = unsafe { CStr::from_ptr(r.context_json) }.to_str().unwrap();
        assert!(json.contains("test"));
    }

    #[test]
    fn test_result_error() {
        let r = DmpResult::error("Something went wrong");
        assert!(r.context_json.is_null());
        assert!(!r.error.is_null());
        let err = unsafe { CStr::from_ptr(r.error) }.to_str().unwrap();
        assert!(err.contains("wrong"));
    }

    #[test]
    fn test_result_free() {
        let r = Box::into_raw(Box::new(DmpResult::ok("{}", "", "")));
        unsafe { dmp_result_free(r) };
        // No crash = pass
    }
}
