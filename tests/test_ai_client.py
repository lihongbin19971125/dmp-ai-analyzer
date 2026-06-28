"""Tests for ai_client.py — multi-backend AI client with DeepSeek/OpenAI/Anthropic."""

import os
from unittest.mock import patch, MagicMock

import pytest

from mvp.ai_client import (
    analyze,
    _default_model,
    _base_url,
    _env_var_name,
    _resolve_api_key,
    _system_message,
    _system_message,
)


# ---------------------------------------------------------------------------
# _default_model
# ---------------------------------------------------------------------------


def test_default_model_deepseek():
    """_default_model('deepseek') returns 'deepseek-chat'."""
    assert _default_model("deepseek") == "deepseek-chat"


def test_default_model_openai():
    """_default_model('openai') returns 'gpt-4o'."""
    assert _default_model("openai") == "gpt-4o"


def test_default_model_anthropic():
    """_default_model('anthropic') returns 'claude-sonnet-4-6'."""
    assert _default_model("anthropic") == "claude-sonnet-4-6"


def test_default_model_unknown():
    """_default_model returns deepseek-chat for unknown provider."""
    assert _default_model("unknown_provider") == "deepseek-chat"


# ---------------------------------------------------------------------------
# _base_url
# ---------------------------------------------------------------------------


def test_base_url_deepseek():
    """_base_url('deepseek') returns DeepSeek API URL."""
    assert _base_url("deepseek") == "https://api.deepseek.com/v1"


def test_base_url_openai():
    """_base_url('openai') returns OpenAI API URL."""
    assert _base_url("openai") == "https://api.openai.com/v1"


# ---------------------------------------------------------------------------
# _env_var_name
# ---------------------------------------------------------------------------


def test_env_var_name_mapping():
    """_env_var_name returns correct env var for each provider."""
    assert _env_var_name("deepseek") == "DEEPSEEK_API_KEY"
    assert _env_var_name("openai") == "OPENAI_API_KEY"
    assert _env_var_name("anthropic") == "ANTHROPIC_API_KEY"
    # Unknown provider falls back to DEEPSEEK_API_KEY
    assert _env_var_name("unknown") == "DEEPSEEK_API_KEY"


# ---------------------------------------------------------------------------
# _resolve_api_key
# ---------------------------------------------------------------------------


def test_resolve_api_key_from_env(monkeypatch):
    """_resolve_api_key reads from the provider-specific env var."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test123")
    result = _resolve_api_key("openai")
    assert result == "sk-test123"


def test_resolve_api_key_fallback_to_generic(monkeypatch):
    """_resolve_api_key falls back to AI_API_KEY when provider-specific var is unset."""
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.setenv("AI_API_KEY", "sk-generic")
    result = _resolve_api_key("deepseek")
    assert result == "sk-generic"


def test_resolve_api_key_none(monkeypatch):
    """_resolve_api_key returns None when no key is set."""
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    result = _resolve_api_key("deepseek")
    assert result is None


# ---------------------------------------------------------------------------
# analyze — error path
# ---------------------------------------------------------------------------


def test_analyze_no_api_key_error(monkeypatch):
    """analyze() raises ValueError when no API key is available."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("AI_API_KEY", raising=False)
    with pytest.raises(ValueError) as exc_info:
        analyze(
            context_json='{"key":"value"}',
            prompt_template="test {CONTEXT}",
            provider="openai",
        )
    assert "No API key found for openai" in str(exc_info.value)
    assert "OPENAI_API_KEY" in str(exc_info.value)


# ---------------------------------------------------------------------------
# analyze — provider routing
# ---------------------------------------------------------------------------


def test_analyze_provider_routing_deepseek():
    """analyze routes deepseek to _call_openai_compatible with correct base_url."""
    with patch("mvp.ai_client._call_openai_compatible") as mock_call:
        mock_call.return_value = "mock analysis result"

        result = analyze(
            context_json='{"meta":{"test":true}}',
            prompt_template="System: {CONTEXT}",
            provider="deepseek",
            api_key="sk-test",
        )

        mock_call.assert_called_once()
        call_args, call_kwargs = mock_call.call_args
        # Positional args: prompt, api_key, model, base_url, timeout
        assert call_args[0] == 'System: {"meta":{"test":true}}'  # prompt
        assert call_args[1] == "sk-test"  # api_key
        assert call_args[2] == "deepseek-chat"  # model (default for deepseek)
        assert call_args[3] == "https://api.deepseek.com/v1"  # base_url
        assert result == "mock analysis result"


def test_analyze_provider_routing_anthropic():
    """analyze routes anthropic to _call_anthropic."""
    with patch("mvp.ai_client._call_anthropic") as mock_call:
        mock_call.return_value = "claude analysis"

        result = analyze(
            context_json='{"meta":{"dump_path":"crash.dmp"}}',
            prompt_template="Debug: {CONTEXT}",
            provider="anthropic",
            api_key="sk-ant-test",
        )

        mock_call.assert_called_once()
        call_args, call_kwargs = mock_call.call_args
        assert call_args[0] == 'Debug: {"meta":{"dump_path":"crash.dmp"}}'  # prompt
        assert call_args[1] == "sk-ant-test"  # api_key
        assert call_args[2] == "claude-sonnet-4-6"  # model (default for anthropic)
        assert result == "claude analysis"


# ---------------------------------------------------------------------------
# analyze — prompt assembly
# ---------------------------------------------------------------------------


def test_prompt_assembly():
    """analyze substitutes {CONTEXT} placeholder with the actual context JSON."""
    context = '{"meta":{"dump_path":"crash.dmp"}}'
    template = "System: {CONTEXT}"

    with patch("mvp.ai_client._call_openai_compatible") as mock_call:
        mock_call.return_value = "analysis"

        analyze(
            context_json=context,
            prompt_template=template,
            provider="deepseek",
            api_key="sk-test",
            model="test-model",
        )

        mock_call.assert_called_once()
        # The first positional argument is the assembled prompt
        prompt = mock_call.call_args[0][0]
        assert "System: " in prompt
        assert '{"meta":{"dump_path":"crash.dmp"}}' in prompt
        assert "{CONTEXT}" not in prompt
        assert prompt == 'System: {"meta":{"dump_path":"crash.dmp"}}'


# ---------------------------------------------------------------------------
# analyze — model override
# ---------------------------------------------------------------------------


def test_model_override():
    """analyze uses explicit model param instead of default when provided."""
    with patch("mvp.ai_client._call_openai_compatible") as mock_call:
        mock_call.return_value = "analysis"

        analyze(
            context_json='{"test":true}',
            prompt_template="{CONTEXT}",
            provider="deepseek",
            api_key="sk-test",
            model="deepseek-reasoner",
        )

        mock_call.assert_called_once()
        model = mock_call.call_args[0][2]
        assert model == "deepseek-reasoner"
        assert model != "deepseek-chat"


# ---------------------------------------------------------------------------
# analyze — explicit api_key param
# ---------------------------------------------------------------------------


def test_api_key_explicit_param(monkeypatch):
    """analyze uses explicitly passed api_key instead of env var."""
    # Set an env key that should be ignored in favor of the explicit param
    monkeypatch.setenv("DEEPSEEK_API_KEY", "env-key")

    with patch("mvp.ai_client._call_openai_compatible") as mock_call:
        mock_call.return_value = "analysis"

        analyze(
            context_json='{"test":true}',
            prompt_template="{CONTEXT}",
            provider="deepseek",
            api_key="explicit-key",
        )

        # Verify the explicit key was passed to the backend
        mock_call.assert_called_once()
        api_key = mock_call.call_args[0][1]
        assert api_key == "explicit-key"
        assert api_key != "env-key"


# ---------------------------------------------------------------------------
# _system_message
# ---------------------------------------------------------------------------


def test_system_message_structure():
    """_system_message returns the expected dict structure and content."""
    msg = _system_message()
    assert isinstance(msg, dict)
    assert msg["role"] == "system"
    assert isinstance(msg["content"], str)
    # Check for key phrases
    content = msg["content"]
    assert "crash dump analysis" in content
    assert "root cause analysis" in content
    assert "Chinese (Simplified)" in content


# ---------------------------------------------------------------------------
# analyze — provider case insensitive
# ---------------------------------------------------------------------------


def test_provider_case_insensitive():
    """analyze lowercases the provider string, so 'DeepSeek' and 'deepseek' are equivalent."""
    with patch("mvp.ai_client._call_openai_compatible") as mock_call:
        mock_call.return_value = "analysis"

        analyze(
            context_json='{"test":true}',
            prompt_template="{CONTEXT}",
            provider="DeepSeek",
            api_key="sk-test",
        )

        mock_call.assert_called_once()
        base_url = mock_call.call_args[0][3]
        # Mixed case should still resolve to the deepseek base URL
        assert base_url == "https://api.deepseek.com/v1"


# ═════════════════════════════════════════════════════════════════════
# Template selection tests
# ═════════════════════════════════════════════════════════════════════

class TestTemplateSelection:
    """Tests for template_selector.select_template()."""

    def test_access_violation_template(self):
        """C0000005 maps to access_violation.md."""
        from mvp.template_selector import select_template
        t = select_template("C0000005")
        assert "ACCESS_VIOLATION" in t
        assert "C0000005" in t

    def test_memory_oom_template(self):
        """C0000017 maps to memory.md."""
        from mvp.template_selector import select_template
        t = select_template("C0000017")
        assert "内存" in t or "memory" in t.lower()

    def test_heap_corruption_template(self):
        """C0000374 maps to memory.md."""
        from mvp.template_selector import select_template
        t = select_template("C0000374")
        assert "HEAP_CORRUPTION" in t or "堆" in t

    def test_stack_overflow_template(self):
        """C00000FD maps to stack_overflow.md."""
        from mvp.template_selector import select_template
        t = select_template("C00000FD")
        assert "STACK_OVERFLOW" in t or "栈" in t

    def test_divide_by_zero_template(self):
        """C0000094 maps to divide_by_zero.md."""
        from mvp.template_selector import select_template
        t = select_template("C0000094")
        assert "除零" in t or "DIVIDE" in t

    def test_clr_exception_template(self):
        """E0434352 maps to clr_exception.md."""
        from mvp.template_selector import select_template
        t = select_template("E0434352")
        assert "CLR" in t or ".NET" in t

    def test_unknown_code_falls_to_generic(self):
        """Unknown exception code falls back to generic.md."""
        from mvp.template_selector import select_template
        t = select_template("DEADBEEF")
        # Generic template should still have the CONTEXT placeholder
        assert "{CONTEXT}" in t

    def test_template_includes_context_placeholder(self):
        """Every template must have {CONTEXT} placeholder."""
        from mvp.template_selector import select_template
        for code in ["C0000005", "C0000017", "C00000FD", "C0000094",
                      "E0434352", "UNKNOWN"]:
            t = select_template(code)
            assert "{CONTEXT}" in t, f"Template for {code} missing {{CONTEXT}}"

    def test_template_contains_role(self):
        """Every specialized template should have role/expertise section."""
        from mvp.template_selector import select_template
        for code in ["C0000005", "C0000017", "C00000FD"]:
            t = select_template(code)
            assert "角色" in t or "expert" in t.lower()


class TestSystemMessage:
    """Tests for _system_message() helper."""

    def test_system_message_structure(self):
        """System message should have correct role and mention debugging."""
        msg = _system_message()
        assert msg["role"] == "system"
        assert "debug" in msg["content"].lower() or "调试" in msg["content"]
