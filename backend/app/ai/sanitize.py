import re
from typing import Any

CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key)\b\s*(?:=|:\s)\s*\S+"),
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}"),
)
REDACTED = "[redacted]"
TEXT_LIMIT = 800
KEY_LIMIT = 80
LIST_LIMIT = 50


def clean_text(value: str, limit: int = TEXT_LIMIT) -> str:
    text = CONTROL_CHARACTERS.sub(" ", value)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    text = " ".join(text.split())
    if len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def sanitize_payload(value: Any) -> Any:
    if isinstance(value, dict):
        return {clean_text(str(key), KEY_LIMIT): sanitize_payload(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize_payload(item) for item in list(value)[:LIST_LIMIT]]
    if isinstance(value, str):
        return clean_text(value)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return clean_text(str(value))