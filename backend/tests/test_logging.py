import json
import logging
import sys

from app.core.logging import JsonFormatter, request_id_var
from support import API


def make_record(message, exc_info=None):
    return logging.LogRecord("app.test", logging.INFO, __file__, 1, message, (), exc_info)


def test_log_lines_are_json_with_a_request_id_and_no_secrets():
    token = request_id_var.set("req-12345678")
    try:
        line = JsonFormatter().format(
            make_record(
                "login with Bearer eyJhbGciOiJIUzI1NiJ9.abcdefghij.klmnopqrst and "
                "password = hunter2 at postgresql+psycopg://user:topsecret@db:5432/app"
            )
        )
    finally:
        request_id_var.reset(token)
    payload = json.loads(line)
    assert payload["request_id"] == "req-12345678"
    assert payload["level"] == "INFO"
    assert payload["logger"] == "app.test"
    for secret in ("eyJhbGci", "hunter2", "topsecret"):
        assert secret not in line


def test_exception_text_is_redacted():
    leaked = "AIza" + "A" * 35
    try:
        raise RuntimeError(f"failed with {leaked}")
    except RuntimeError:
        info = sys.exc_info()
    payload = json.loads(JsonFormatter().format(make_record("boom", info)))
    assert "RuntimeError" in payload["exception"]
    assert "AIza" not in payload["exception"]


def test_request_log_lines_do_not_include_query_strings(client, caplog):
    caplog.set_level(logging.INFO, logger="app.access")
    client.get(f"{API}/health?token=supersecretvalue")
    messages = [record.getMessage() for record in caplog.records if record.name == "app.access"]
    assert any(message.startswith("GET /api/v1/health -> 200") for message in messages)
    assert all("supersecretvalue" not in message for message in messages)