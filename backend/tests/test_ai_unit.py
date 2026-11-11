from types import SimpleNamespace
from engine_support import allow, bucket, document, policy, user_arn

import httpx
import pytest
from google.genai import errors as genai_errors

from app.ai.errors import (
    AIInvalidResponseError,
    AINotConfiguredError,
    AIProviderError,
    AIQuotaError,
    AITimeoutError,
)
from app.ai.gemini import GeminiAnalyst
from app.ai.prompts import compact_evidence, fit_to_budget, payload_size
from app.ai.sanitize import clean_text, sanitize_payload
from app.ai.schemas import SecuritySummaryOutput, check_limits
from app.core.config import Settings
from ai_support import finding_output, summary_output


def make_settings(api_key: str = "", model: str = "") -> Settings:
    return Settings(
        database_url="postgresql+psycopg://user:pass@localhost/db",
        jwt_secret_key="x" * 32,
        gemini_api_key=api_key,
        gemini_model=model,
    )


class FakeAPIError(genai_errors.APIError):
    def __init__(self, code: int) -> None:
        self.code = code
        self.message = "provider detail that must not leak"
        self.status = "ERROR"


class FakeClient:
    def __init__(self, behavior) -> None:
        self.models = SimpleNamespace(generate_content=lambda **kwargs: behavior())


def analyst_with(monkeypatch, behavior) -> GeminiAnalyst:
    monkeypatch.setattr(
        "app.ai.gemini._build_client", lambda api_key, timeout_ms: FakeClient(behavior)
    )
    return GeminiAnalyst(make_settings("test-key", "test-model"))


def generate(analyst: GeminiAnalyst):
    return analyst.generate("system", {"task": "x"}, SecuritySummaryOutput)


def test_control_characters_are_removed_and_whitespace_collapsed():
    assert clean_text("a\x00b\n\n c") == "a b c"


def test_secrets_are_redacted():
    text = (
        "key AKIAABCDEFGHIJKLMNOP and AIza" + "A" * 35 + " password = hunter2 token: abc "
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signaturevalue"
    )
    cleaned = clean_text(text)
    for secret in ("AKIAABCDEFGHIJKLMNOP", "hunter2", "eyJhbGci", "AIzaAAAA"):
        assert secret not in cleaned
    assert "[redacted]" in cleaned


def test_resource_arns_are_not_mistaken_for_secrets():
    arn = "arn:aws:secretsmanager:us-east-1:111122223333:secret:prod/db-password"
    assert clean_text(arn) == arn


def test_long_text_is_truncated():
    assert len(clean_text("word " * 500)) == 800


def test_payload_sanitizing_is_recursive_and_caps_lists():
    cleaned = sanitize_payload({"name\x00": ["AKIAABCDEFGHIJKLMNOP"] * 60, "count": 3, "flag": True})
    assert "name" in cleaned
    assert "name\x00" not in cleaned
    assert cleaned["count"] == 3
    assert cleaned["flag"] is True
    assert len(cleaned["name"]) == 50
    assert cleaned["name"][0] == "[redacted]"


def test_check_limits_rejects_bad_output():
    check_limits(finding_output())
    too_long = finding_output().model_copy(update={"why_it_is_risky": "x " * 700})
    empty = finding_output().model_copy(update={"what_was_detected": "  "})
    too_many = finding_output().model_copy(update={"evidence_established": ["a"] * 9})
    for bad in (too_long, empty, too_many):
        with pytest.raises(AIInvalidResponseError):
            check_limits(bad)


def test_compact_evidence_keeps_only_known_keys():
    items = [{"kind": "policy_statement", "secret_field": "x", "actions": ["s3:*"], "statements": [{"effect": "allow", "extra": 1}]}]
    assert compact_evidence(items) == [
        {"kind": "policy_statement", "actions": ["s3:*"], "statements": [{"effect": "allow"}]}
    ]


def test_fit_to_budget_trims_evidence():
    payload = {"finding": {"evidence": [{"kind": "x", "notes": ["n" * 200]} for _ in range(20)]}}
    fitted = fit_to_budget(payload, 1500)
    assert payload_size(fitted) <= 1500 or fitted["finding"]["evidence"] == []
    assert len(fitted["finding"]["evidence"]) < 20


def test_unconfigured_analyst_never_calls_the_provider(monkeypatch):
    def fail(api_key, timeout_ms):
        raise AssertionError("client must not be created")

    monkeypatch.setattr("app.ai.gemini._build_client", fail)
    analyst = GeminiAnalyst(make_settings())
    assert analyst.is_configured is False
    with pytest.raises(AINotConfiguredError):
        generate(analyst)


def test_valid_response_is_parsed(monkeypatch):
    analyst = analyst_with(
        monkeypatch, lambda: SimpleNamespace(text=summary_output().model_dump_json())
    )
    assert generate(analyst).overview == summary_output().overview


@pytest.mark.parametrize("text", [None, "", "not json", '{"overview": "x"}'])
def test_unusable_responses_are_rejected(monkeypatch, text):
    analyst = analyst_with(monkeypatch, lambda: SimpleNamespace(text=text))
    with pytest.raises(AIInvalidResponseError):
        generate(analyst)


def test_oversized_response_is_rejected(monkeypatch):
    oversized = summary_output().model_copy(update={"overview": "x " * 700})
    analyst = analyst_with(monkeypatch, lambda: SimpleNamespace(text=oversized.model_dump_json()))
    with pytest.raises(AIInvalidResponseError):
        generate(analyst)


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        (429, AIQuotaError),
        (504, AITimeoutError),
        (403, AIProviderError),
        (404, AIProviderError),
        (500, AIProviderError),
    ],
)
def test_provider_status_codes_are_mapped(monkeypatch, code, expected):
    def fail():
        raise FakeAPIError(code)

    with pytest.raises(expected) as raised:
        generate(analyst_with(monkeypatch, fail))
    assert "provider detail" not in raised.value.message


def test_network_errors_are_mapped(monkeypatch):
    def timeout():
        raise httpx.ReadTimeout("slow")

    def refused():
        raise httpx.ConnectError("refused")

    with pytest.raises(AITimeoutError):
        generate(analyst_with(monkeypatch, timeout))
    with pytest.raises(AIProviderError):
        generate(analyst_with(monkeypatch, refused))