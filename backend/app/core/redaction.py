import re

REDACTED = "[redacted]"
CREDENTIALS_IN_URL = re.compile(r"://[^\s/:@]+:[^\s/@]+@")
SECRET_PATTERNS = (
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    re.compile(r"(?i)\b(?:password|passwd|secret|token|api[_-]?key)\b\s*(?:=|:\s)\s*\S+"),
    re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}"),
)


def redact(text: str) -> str:
    text = CREDENTIALS_IN_URL.sub(f"://{REDACTED}@", text)
    for pattern in SECRET_PATTERNS:
        text = pattern.sub(REDACTED, text)
    return text