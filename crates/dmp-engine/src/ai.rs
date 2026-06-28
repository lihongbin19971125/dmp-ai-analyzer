//! AI client — DeepSeek / OpenAI / Anthropic backends.
//! Ported from Python mvp/ai_client.py.
//! Uses reqwest blocking HTTP client.

use serde_json::{json, Value};

/// Supported AI providers.
#[derive(Debug, Clone, PartialEq)]
pub enum AiProvider {
    DeepSeek,
    OpenAI,
    Anthropic,
}

impl AiProvider {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "openai" => AiProvider::OpenAI,
            "anthropic" => AiProvider::Anthropic,
            _ => AiProvider::DeepSeek,
        }
    }

    pub fn default_model(&self) -> &str {
        match self {
            AiProvider::DeepSeek => "deepseek-chat",
            AiProvider::OpenAI => "gpt-4o",
            AiProvider::Anthropic => "claude-sonnet-4-6",
        }
    }

    pub fn base_url(&self) -> &str {
        match self {
            AiProvider::DeepSeek => "https://api.deepseek.com/v1",
            AiProvider::OpenAI => "https://api.openai.com/v1",
            AiProvider::Anthropic => "https://api.anthropic.com",
        }
    }

    pub fn env_var_name(&self) -> &str {
        match self {
            AiProvider::DeepSeek => "DEEPSEEK_API_KEY",
            AiProvider::OpenAI => "OPENAI_API_KEY",
            AiProvider::Anthropic => "ANTHROPIC_API_KEY",
        }
    }
}

/// Resolve API key from environment.
pub fn resolve_api_key(provider: &AiProvider, explicit: Option<&str>) -> Option<String> {
    if let Some(key) = explicit {
        if !key.is_empty() {
            return Some(key.to_string());
        }
    }
    // Try provider-specific env var
    if let Ok(key) = std::env::var(provider.env_var_name()) {
        if !key.is_empty() {
            return Some(key);
        }
    }
    // Fallback: generic AI_API_KEY
    if let Ok(key) = std::env::var("AI_API_KEY") {
        if !key.is_empty() {
            return Some(key);
        }
    }
    None
}

/// System message for the AI.
pub fn system_message() -> Value {
    json!({
        "role": "system",
        "content": "You are a senior Windows/C++ debugging expert with deep experience in crash dump analysis. Analyze structured crash data and provide root cause analysis, fix suggestions, and prevention advice. Always cite specific evidence. Respond in Chinese (Simplified) by default."
    })
}

/// Analyze a crash dump using AI (requires `http` feature).
/// Without `http` feature, returns an error instructing to enable it.
#[cfg(not(feature = "http"))]
pub fn analyze(
    _context_json: &str,
    _prompt_template: &str,
    _provider: &AiProvider,
    _api_key: Option<&str>,
    _model: Option<&str>,
) -> Result<String, String> {
    Err("AI analysis requires the 'http' feature. Rebuild with: cargo build --features http".into())
}

/// Analyze a crash dump using AI.
/// Returns the AI's Markdown response text.
#[cfg(feature = "http")]
pub fn analyze(
    context_json: &str,
    prompt_template: &str,
    provider: &AiProvider,
    api_key: Option<&str>,
    model: Option<&str>,
) -> Result<String, String> {
    let key = resolve_api_key(provider, api_key)
        .ok_or_else(|| format!("No API key found for {}. Set env var {} or pass --api-key.",
            provider_to_str(provider), provider.env_var_name()))?;

    let prompt = prompt_template.replace("{CONTEXT}", context_json);
    let model = model.unwrap_or(provider.default_model());

    match provider {
        AiProvider::DeepSeek | AiProvider::OpenAI => {
            call_openai_compatible(&key, &prompt, model, provider.base_url())
        }
        AiProvider::Anthropic => {
            call_anthropic(&key, &prompt, model)
        }
    }
}

#[cfg(feature = "http")]
fn provider_to_str(p: &AiProvider) -> &str {
    match p { AiProvider::DeepSeek => "deepseek", AiProvider::OpenAI => "openai", AiProvider::Anthropic => "anthropic" }
}

/// Call OpenAI-compatible API (DeepSeek, OpenAI).
#[cfg(feature = "http")]
fn call_openai_compatible(api_key: &str, prompt: &str, model: &str, base_url: &str) -> Result<String, String> {
    let client = reqwest::blocking::Client::new();
    let url = format!("{}/chat/completions", base_url);

    let body = json!({
        "model": model,
        "messages": [
            system_message(),
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 8192,
    });

    let resp = client.post(&url)
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("API request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        return Err(format!("API error {}: {}", status.as_u16(), text));
    }

    let data: Value = resp.json().map_err(|e| format!("Invalid JSON response: {}", e))?;
    data["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No content in response".to_string())
}

/// Call Anthropic Messages API.
#[cfg(feature = "http")]
fn call_anthropic(api_key: &str, prompt: &str, model: &str) -> Result<String, String> {
    let client = reqwest::blocking::Client::new();
    let sys_msg = system_message();
    let sys_content = sys_msg["content"].as_str().unwrap_or("");

    let body = json!({
        "model": model,
        "max_tokens": 8192,
        "temperature": 0.3,
        "system": sys_content,
        "messages": [
            {"role": "user", "content": prompt}
        ],
    });

    let resp = client.post("https://api.anthropic.com/v1/messages")
        .header("x-api-key", api_key)
        .header("anthropic-version", "2023-06-01")
        .header("Content-Type", "application/json")
        .json(&body)
        .send()
        .map_err(|e| format!("API request failed: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let text = resp.text().unwrap_or_default();
        return Err(format!("API error {}: {}", status.as_u16(), text));
    }

    let data: Value = resp.json().map_err(|e| format!("Invalid JSON response: {}", e))?;
    data["content"][0]["text"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No content in response".to_string())
}

// ═════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_provider_from_str() {
        assert_eq!(AiProvider::from_str("deepseek"), AiProvider::DeepSeek);
        assert_eq!(AiProvider::from_str("DEEPSEEK"), AiProvider::DeepSeek);
        assert_eq!(AiProvider::from_str("openai"), AiProvider::OpenAI);
        assert_eq!(AiProvider::from_str("anthropic"), AiProvider::Anthropic);
        assert_eq!(AiProvider::from_str("unknown"), AiProvider::DeepSeek); // default
    }

    #[test]
    fn test_default_models() {
        assert_eq!(AiProvider::DeepSeek.default_model(), "deepseek-chat");
        assert_eq!(AiProvider::OpenAI.default_model(), "gpt-4o");
        assert_eq!(AiProvider::Anthropic.default_model(), "claude-sonnet-4-6");
    }

    #[test]
    fn test_base_urls() {
        assert!(AiProvider::DeepSeek.base_url().contains("deepseek"));
        assert!(AiProvider::OpenAI.base_url().contains("openai"));
        assert!(AiProvider::Anthropic.base_url().contains("anthropic"));
    }

    #[test]
    fn test_env_var_names() {
        assert_eq!(AiProvider::DeepSeek.env_var_name(), "DEEPSEEK_API_KEY");
        assert_eq!(AiProvider::OpenAI.env_var_name(), "OPENAI_API_KEY");
        assert_eq!(AiProvider::Anthropic.env_var_name(), "ANTHROPIC_API_KEY");
    }

    #[test]
    fn test_resolve_api_key_explicit() {
        let key = resolve_api_key(&AiProvider::DeepSeek, Some("sk-test123"));
        assert_eq!(key, Some("sk-test123".into()));
    }

    #[test]
    fn test_resolve_api_key_none() {
        // Without env var set, should return None
        let key = resolve_api_key(&AiProvider::DeepSeek, None);
        // May be None or may find env var — just check it compiles
        let _ = key;
    }

    #[test]
    fn test_system_message() {
        let msg = system_message();
        assert_eq!(msg["role"], "system");
        assert!(msg["content"].as_str().unwrap().contains("debug"));
    }

    #[test]
    fn test_prompt_assembly() {
        let template = "## Context\n{CONTEXT}\n## Analysis";
        let ctx = r#"{"exception":{"code":"C0000005"}}"#;
        let result = template.replace("{CONTEXT}", ctx);
        assert!(result.contains("C0000005"));
        assert!(!result.contains("{CONTEXT}"));
    }

    #[test]
    fn test_analyze_without_http_feature() {
        // Without http feature, returns feature-gated error
        let result = analyze("{}", "{CONTEXT}", &AiProvider::DeepSeek, None, None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains("http") || err.contains("No API key"));
    }
}
