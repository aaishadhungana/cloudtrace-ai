import re
from typing import Any

from app.core.redaction import redact

CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
TEXT_LIMIT = 800
KEY_LIMIT = 80
LIST_LIMIT = 50


def clean_text(value: str, limit: int = TEXT_LIMIT) -> str:
    text = redact(CONTROL_CHARACTERS.sub(" ", value))
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