"""AI prompt template selection based on exception type.

Maps exception codes to specialized prompt templates that include
analysis focus areas, evidence checklists, and specific recommendations
for each exception category.
"""

from pathlib import Path

_EXCEPTION_TO_TEMPLATE: dict[str, str] = {
    # Access violations
    "C0000005": "access_violation.md",
    "C0000409": "access_violation.md",       # Stack buffer overrun

    # Memory issues
    "C0000017": "memory.md",                  # STATUS_NO_MEMORY
    "C0000374": "memory.md",                  # HEAP_CORRUPTION

    # Stack overflow
    "C00000FD": "stack_overflow.md",

    # Divide by zero
    "C0000094": "divide_by_zero.md",          # INTEGER_DIVIDE_BY_ZERO
    "C000008E": "divide_by_zero.md",          # FLOAT_DIVIDE_BY_ZERO

    # CLR / .NET Managed
    "E0434352": "clr_exception.md",
    "E0434F4D": "clr_exception.md",
}

_TEMPLATE_DIR = Path(__file__).parent / "prompt_templates"
_LEGACY_TEMPLATE = Path(__file__).parent / "prompt_template.md"


def select_template(exception_code: str) -> str:
    """Select the best prompt template for the given exception code.

    Fallback chain: specialized → generic → legacy prompt_template.md.
    None of these should fail — the legacy template is the original.

    Args:
        exception_code: Hex exception code string (e.g. "C0000005").

    Returns:
        Prompt template Markdown text.
    """
    template_name = _EXCEPTION_TO_TEMPLATE.get(exception_code, "generic.md")
    template_path = _TEMPLATE_DIR / template_name

    if template_path.is_file():
        return template_path.read_text(encoding="utf-8")

    # Fall back to generic (inside the new directory)
    generic_path = _TEMPLATE_DIR / "generic.md"
    if generic_path.is_file():
        return generic_path.read_text(encoding="utf-8")

    # Ultimate fallback: the original prompt_template.md
    if _LEGACY_TEMPLATE.is_file():
        return _LEGACY_TEMPLATE.read_text(encoding="utf-8")

    # Should never happen, but provide a minimal template as last resort
    return "## 角色\n你是 Windows 调试专家。\n\n## 崩溃数据\n{CONTEXT}\n\n请分析根因。"
