"""Multi-backend AI client.

Supports DeepSeek (default), OpenAI, and Anthropic backends
through a unified interface.
"""

import json
import os
import re
from typing import Optional


# ---------------------------------------------------------------------------
# Unified client
# ---------------------------------------------------------------------------

def analyze(
    context_json: str,
    prompt_template: str,
    provider: str = "deepseek",
    api_key: Optional[str] = None,
    model: Optional[str] = None,
    timeout: int = 120,
) -> str:
    """Send analysis context to AI and return the analysis result.

    Args:
        context_json: JSON-serialized AnalysisContext.
        prompt_template: The prompt template with a {CONTEXT} placeholder.
        provider: "deepseek" (default), "openai", or "anthropic".
        api_key: API key (or read from env var).
        model: Model name override.
        timeout: API timeout in seconds.

    Returns:
        AI analysis result as Markdown text.
    """
    # Resolve defaults
    provider = provider.lower()
    if not model:
        model = _default_model(provider)
    if not api_key:
        api_key = _resolve_api_key(provider)

    if not api_key:
        raise ValueError(
            f"No API key found for {provider}. "
            f"Set environment variable {_env_var_name(provider)} "
            f"or pass --api-key."
        )

    # Assemble prompt
    full_prompt = prompt_template.replace("{CONTEXT}", context_json)

    # Route to backend
    if provider == "anthropic":
        result = _call_anthropic(full_prompt, api_key, model, timeout)
    else:
        # Both DeepSeek and OpenAI use the OpenAI-compatible API
        base_url = _base_url(provider)
        result = _call_openai_compatible(full_prompt, api_key, model,
                                         base_url, timeout)

    return result


# ---------------------------------------------------------------------------
# Backend implementations
# ---------------------------------------------------------------------------

def _call_openai_compatible(
    prompt: str,
    api_key: str,
    model: str,
    base_url: str,
    timeout: int,
) -> str:
    """Call an OpenAI-compatible API (DeepSeek or OpenAI).

    Supports both openai SDK v0.x (legacy) and v1.x (current).
    """
    import openai

    # Detect SDK version
    if hasattr(openai, "OpenAI"):
        # ── openai SDK v1.x ──
        client = openai.OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)
        response = client.chat.completions.create(
            model=model,
            messages=[
                _system_message(),
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=8192,
        )
        return response.choices[0].message.content or ""

    else:
        # ── openai SDK v0.x (legacy) ──
        openai.api_key = api_key
        openai.api_base = base_url
        response = openai.ChatCompletion.create(
            model=model,
            messages=[
                _system_message(),
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            max_tokens=8192,
            request_timeout=timeout,
        )
        return response.choices[0].message.content or ""


def _call_anthropic(
    prompt: str,
    api_key: str,
    model: str,
    timeout: int,
) -> str:
    """Call the Anthropic (Claude) API."""
    import anthropic

    client = anthropic.Anthropic(api_key=api_key, timeout=timeout)

    response = client.messages.create(
        model=model,
        max_tokens=8192,
        temperature=0.3,
        system=_system_message()["content"],
        messages=[{"role": "user", "content": prompt}],
    )

    # Anthropic returns content blocks
    return response.content[0].text if response.content else ""


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def _default_model(provider: str) -> str:
    models = {
        "deepseek": "deepseek-chat",
        "openai": "gpt-4o",
        "anthropic": "claude-sonnet-4-6",
    }
    return models.get(provider, "deepseek-chat")


def _base_url(provider: str) -> str:
    urls = {
        "deepseek": "https://api.deepseek.com/v1",
        "openai": "https://api.openai.com/v1",
    }
    return urls.get(provider, urls["deepseek"])


def _env_var_name(provider: str) -> str:
    names = {
        "deepseek": "DEEPSEEK_API_KEY",
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
    }
    return names.get(provider, "DEEPSEEK_API_KEY")


def _resolve_api_key(provider: str) -> Optional[str]:
    """Resolve API key from environment or common config files."""
    env_var = _env_var_name(provider)
    key = os.environ.get(env_var)
    if key:
        return key
    # Also check a generic AI_API_KEY as fallback
    return os.environ.get("AI_API_KEY")


def _system_message() -> dict:
    return {
        "role": "system",
        "content": (
            "You are a senior Windows/C++ debugging expert with deep experience "
            "in crash dump analysis. You analyze structured crash data and "
            "provide root cause analysis, fix suggestions, and prevention advice. "
            "Always cite specific evidence from the provided data. "
            "If information is insufficient, clearly state what is missing. "
            "Respond in Chinese (Simplified) by default."
        ),
    }
