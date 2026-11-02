import re
from collections.abc import Iterable
from functools import lru_cache


@lru_cache(maxsize=8192)
def _compile(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    expression = "".join(
        ".*" if char == "*" else "." if char == "?" else re.escape(char) for char in pattern
    )
    flags = re.IGNORECASE if ignore_case else re.NOFLAG
    return re.compile(f"^{expression}$", flags | re.DOTALL)


def matches_action(pattern: str, action: str) -> bool:
    return _compile(pattern, True).match(action) is not None


def matches_resource(pattern: str, arn: str) -> bool:
    return _compile(pattern, False).match(arn) is not None


def resource_part(pattern: str) -> str:
    if pattern.startswith("arn:"):
        parts = pattern.split(":", 5)
        if len(parts) == 6:
            return parts[5]
    return pattern


def is_broad_resource(pattern: str, target_arns: Iterable[str]) -> bool:
    part = resource_part(pattern)
    if pattern == "*" or part == "*":
        return True
    name_segment = part.split("/", 1)[0]
    if "*" in name_segment or "?" in name_segment:
        return True
    matched = sum(
        1
        for arn in target_arns
        if matches_resource(pattern, arn) or matches_resource(pattern, f"{arn}/*")
    )
    return matched >= 2