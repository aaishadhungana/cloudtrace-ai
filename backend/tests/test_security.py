import re
import uuid

from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
import pytest

from app.core.config import Settings, get_settings
from app.db.session import engine
from app.main import app, create_app
from support import API

PUBLIC_ROUTES = {
    ("GET", f"{API}/health"),
    ("POST", f"{API}/auth/register"),
    ("POST", f"{API}/auth/login"),
}
BODY_METHODS = {"POST", "PUT", "PATCH"}


def make_settings(**overrides) -> Settings:
    values = {
        "database_url": "postgresql+psycopg://user:pass@localhost/db",
        "jwt_secret_key": "k" * 40,
        "cors_origins": "http://localhost:3000",
    }
    values.update(overrides)
    return Settings(**values)


def protected_routes() -> list[tuple[str, str]]:
    found = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or not route.path.startswith(API):
            continue
        for method in sorted(route.methods - {"HEAD", "OPTIONS"}):
            if (method, route.path) not in PUBLIC_ROUTES:
                found.append((method, route.path))
    return found


def call(client, method, path, headers):
    url = re.sub(r"\{[^}]+\}", str(uuid.uuid4()), path)
    kwargs = {"json": {}} if method in BODY_METHODS else {}
    return client.request(method, url, headers=headers, **kwargs)


def test_every_route_except_the_public_ones_requires_a_valid_token(client):
    routes = protected_routes()
    assert len(routes) > 20
    failures = []
    for method, path in routes:
        for headers in ({}, {"Authorization": "Bearer not-a-real-token"}):
            status_code = call(client, method, path, headers).status_code
            if status_code != 401:
                failures.append((method, path, status_code, bool(headers)))
    assert failures == []


def test_security_headers_are_set_on_every_response(client):
    for path in (f"{API}/health", f"{API}/auth/me", f"{API}/does-not-exist"):
        response = client.get(path)
        assert response.headers["x-content-type-options"] == "nosniff"
        assert response.headers["x-frame-options"] == "DENY"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["x-request-id"]
        assert "strict-transport-security" not in response.headers


def test_hsts_is_only_sent_in_production(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "app_env", "production")
    response = client.get(f"{API}/health")
    assert "max-age" in response.headers["strict-transport-security"]


def test_request_id_is_echoed_when_valid_and_replaced_when_not(client):
    valid = client.get(f"{API}/health", headers={"X-Request-ID": "abc12345-def"})
    assert valid.headers["x-request-id"] == "abc12345-def"
    for bad in ("short", "has spaces in it 12345", "x" * 100, "bad;id=12345678"):
        response = client.get(f"{API}/health", headers={"X-Request-ID": bad})
        assert re.fullmatch(r"[0-9a-f]{32}", response.headers["x-request-id"])


def test_oversized_request_bodies_are_rejected_before_parsing(client, monkeypatch):
    monkeypatch.setattr(get_settings(), "max_request_bytes", 1024)
    response = client.post(
        f"{API}/auth/login", content=b"x" * 2048, headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body is too large"}


def test_chunked_uploads_without_a_length_are_refused(client):
    response = client.post(
        f"{API}/auth/login",
        content=iter([b"{}"]),
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 411


def test_unhandled_errors_return_a_generic_response(client, auth_headers, monkeypatch):
    def explode(db, user):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr("app.api.dashboard.build_dashboard", explode)
    response = client.get(f"{API}/dashboard", headers=auth_headers)
    assert response.status_code == 500
    assert response.json() == {"detail": "Internal server error"}
    assert "secret internal detail" not in response.text
    assert response.headers["x-request-id"]


def test_placeholder_jwt_secret_is_rejected():
    with pytest.raises(ValueError):
        make_settings(jwt_secret_key="generate_a_long_random_value_before_starting")


def test_wildcard_cors_origin_is_rejected():
    with pytest.raises(ValueError):
        make_settings(cors_origins="*")
    with pytest.raises(ValueError):
        make_settings(cors_origins="http://localhost:3000,*")


def test_production_requires_https_origins():
    with pytest.raises(ValueError):
        make_settings(app_env="production", cors_origins="http://example.com")
    assert make_settings(app_env="production", cors_origins="https://example.com").is_production


def test_docs_are_disabled_in_production(monkeypatch):
    monkeypatch.setattr(
        "app.main.get_settings",
        lambda: make_settings(app_env="production", cors_origins="https://example.com"),
    )
    production = TestClient(create_app())
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert production.get(path).status_code == 404


def test_docs_are_available_in_development(client):
    assert client.get("/docs").status_code == 200


def test_database_errors_do_not_include_query_parameters():
    assert engine.hide_parameters is True