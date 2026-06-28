//! AI prompt template selection by exception type.
//! Ported from Python mvp/template_selector.py.

use std::collections::HashMap;
use std::path::PathBuf;

pub struct TemplateSelector {
    templates_dir: PathBuf,
    legacy_path: PathBuf,
    mapping: HashMap<String, String>,
}

impl TemplateSelector {
    pub fn new(templates_dir: PathBuf, legacy_path: PathBuf) -> Self {
        let mut mapping = HashMap::new();
        mapping.insert("C0000005".into(), "access_violation.md".into());
        mapping.insert("C0000409".into(), "access_violation.md".into());
        mapping.insert("C0000017".into(), "memory.md".into());
        mapping.insert("C0000374".into(), "memory.md".into());
        mapping.insert("C00000FD".into(), "stack_overflow.md".into());
        mapping.insert("C0000094".into(), "divide_by_zero.md".into());
        mapping.insert("C000008E".into(), "divide_by_zero.md".into());
        mapping.insert("E0434352".into(), "clr_exception.md".into());
        mapping.insert("E0434F4D".into(), "clr_exception.md".into());

        Self { templates_dir, legacy_path, mapping }
    }

    pub fn select(&self, exception_code: &str) -> String {
        let template_name = self.mapping.get(exception_code)
            .map(|s| s.as_str())
            .unwrap_or("generic.md");

        let path = self.templates_dir.join(template_name);
        if path.is_file() {
            return std::fs::read_to_string(&path).unwrap_or_else(|_| self.fallback_minimal());
        }

        let generic = self.templates_dir.join("generic.md");
        if generic.is_file() {
            return std::fs::read_to_string(&generic).unwrap_or_else(|_| self.fallback_minimal());
        }

        if self.legacy_path.is_file() {
            return std::fs::read_to_string(&self.legacy_path).unwrap_or_else(|_| self.fallback_minimal());
        }

        self.fallback_minimal()
    }

    fn fallback_minimal(&self) -> String {
        "## 角色\n你是 Windows 调试专家。\n\n## 崩溃数据\n{CONTEXT}\n\n请分析根因。".into()
    }
}

// ═════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_selector(tmp: &std::path::Path) -> TemplateSelector {
        let dir = tmp.join("prompt_templates");
        std::fs::create_dir_all(&dir).unwrap();

        // Create access_violation.md
        std::fs::write(dir.join("access_violation.md"),
            "## ACCESS_VIOLATION 分析\n{CONTEXT}\n## 重点检查空指针").unwrap();
        // Create generic.md
        std::fs::write(dir.join("generic.md"),
            "## 通用分析\n{CONTEXT}").unwrap();
        // Create legacy
        std::fs::write(tmp.join("prompt_template.md"),
            "## Legacy template\n{CONTEXT}").unwrap();

        TemplateSelector::new(dir, tmp.join("prompt_template.md"))
    }

    #[test]
    fn test_select_access_violation() {
        let tmp = std::env::temp_dir().join(format!("dmp_tpl_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let sel = setup_selector(&tmp);
        let t = sel.select("C0000005");
        assert!(t.contains("ACCESS_VIOLATION"));
        assert!(t.contains("空指针"));
    }

    #[test]
    fn test_select_memory_oom() {
        let tmp = std::env::temp_dir().join(format!("dmp_tpl2_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let sel = setup_selector(&tmp);
        let t = sel.select("C0000017");
        // Falls to generic if memory.md doesn't exist
        assert!(t.contains("{CONTEXT}"));
    }

    #[test]
    fn test_select_unknown_falls_to_generic() {
        let tmp = std::env::temp_dir().join(format!("dmp_tpl3_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let sel = setup_selector(&tmp);
        let t = sel.select("BEEF1234");
        assert!(t.contains("{CONTEXT}"));
    }

    #[test]
    fn test_select_empty_dir_falls_to_legacy() {
        let tmp = std::env::temp_dir().join(format!("dmp_tpl4_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();
        let empty_dir = tmp.join("empty");
        std::fs::create_dir_all(&empty_dir).unwrap();
        let legacy = tmp.join("legacy.md");
        std::fs::write(&legacy, "## Legacy fallback\n{CONTEXT}").unwrap();
        let sel = TemplateSelector::new(empty_dir, legacy);
        let t = sel.select("C0000005");
        assert!(t.contains("Legacy fallback"));
    }
}
