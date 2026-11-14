import pytest

from app.api.limits import limiter
from app.core.config import get_settings
from app.core.rate_limit import RateLimiter
from ai_support import FakeAnalyst, ai_url, analyzed, runs_url, use_analyst
from support import API, TEST_PASSWORD, create_environment, post_import, unique_email


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def limits_on(monkeypatch):
    monkeypatch.setattr(get_settings(), "rate_limit_enabled", True)
    limiter.reset()
    yield
    limiter.reset()


def attempt_login(client, headers=None):
    return client.post(
        f"{API}/auth/login",
        json={"email": unique_email(), "password": TEST_PASSWORD},
        headers=headers or {},
    )


def test_blocks_after_the_limit_and_reports_how_long_to_wait():
    clock = Clock()
    limiter_under_test = RateLimiter(clock)
    for _ in range(3):
        assert limiter_under_test.hit("k", 3, 60) is None
    assert limiter_under_test.hit("k", 3, 60) == 60
    clock.now = 30
    assert limiter_under_test.hit("k", 3, 60) == 30
    clock.now = 61
    assert limiter_under_test.hit("k", 3, 60) is None


def test_window_slides_and_keys_are_independent():
    clock = Clock()
    limiter_under_test = RateLimiter(clock)
    for moment in (0, 10, 20):
        clock.now = moment
        assert limiter_under_test.hit("a", 3, 30) is None
    clock.now = 25
    assert limiter_under_test.hit("a", 3, 30) == 5
    assert limiter_under_test.hit("b", 3, 30) is None
    clock.now = 31
    assert limiter_under_test.hit("a", 3, 30) is None
    assert limiter_under_test.hit("a", 3, 30) == 9


def test_idle_keys_are_purged_when_the_table_is_full():
    clock = Clock()
    limiter_under_test = RateLimiter(clock, max_keys=3)
    for key in ("a", "b", "c", "d"):
        limiter_under_test.hit(key, 1, 10)
    assert len(limiter_under_test) == 4
    clock.now = 100
    limiter_under_test.hit("e", 1, 10)
    assert len(limiter_under_test) == 1


def test_reset_clears_everything():
    limiter_under_test = RateLimiter(Clock())
    limiter_under_test.hit("a", 1, 60)
    limiter_under_test.reset()
    assert len(limiter_under_test) == 0
    assert limiter_under_test.hit("a", 1, 60) is None


def test_login_attempts_are_limited_per_client(client, limits_on):
    for _ in range(10):
        assert attempt_login(client).status_code == 401
    blocked = attempt_login(client)
    assert blocked.status_code == 429
    assert blocked.json() == {"detail": "Too many requests. Try again later."}
    assert int(blocked.headers["retry-after"]) > 0


def test_registrations_are_limited_per_client(client, limits_on):
    for _ in range(5):
        response = client.post(
            f"{API}/auth/register", json={"email": unique_email(), "password": TEST_PASSWORD}
        )
        assert response.status_code == 201
    blocked = client.post(
        f"{API}/auth/register", json={"email": unique_email(), "password": TEST_PASSWORD}
    )
    assert blocked.status_code == 429


def test_imports_are_limited_per_user(client, auth_headers, other_auth_headers, limits_on):
    environment = create_environment(client, auth_headers)
    for _ in range(20):
        assert post_import(client, auth_headers, environment["id"], b"{}").status_code == 422
    assert post_import(client, auth_headers, environment["id"], b"{}").status_code == 429
    other = post_import(client, other_auth_headers, environment["id"], b"{}")
    assert other.status_code == 404


def test_analysis_runs_are_limited_per_user(client, auth_headers, limits_on):
    from app.samples.catalog import read_sample

    environment = create_environment(client, auth_headers)
    assert post_import(client, auth_headers, environment["id"], read_sample("acme-dev")).status_code == 201
    for _ in range(10):
        assert client.post(runs_url(environment["id"]), headers=auth_headers).status_code == 201
    assert client.post(runs_url(environment["id"]), headers=auth_headers).status_code == 429


def test_ai_requests_are_limited_even_when_cached(client, auth_headers, limits_on):
    environment, run = analyzed(client, auth_headers)
    fake = use_analyst(FakeAnalyst())
    url = ai_url(environment["id"], run["id"], "summary")
    for _ in range(10):
        assert client.post(url, headers=auth_headers).status_code == 200
    assert client.post(url, headers=auth_headers).status_code == 429
    assert len(fake.calls) == 1


def test_forwarded_header_is_ignored_unless_proxies_are_trusted(client, limits_on):
    for _ in range(10):
        assert attempt_login(client, {"X-Forwarded-For": "9.9.9.1"}).status_code == 401
    assert attempt_login(client, {"X-Forwarded-For": "9.9.9.2"}).status_code == 429


def test_trusted_proxy_header_separates_clients(client, limits_on, monkeypatch):
    monkeypatch.setattr(get_settings(), "trust_proxy_headers", True)
    for _ in range(10):
        assert attempt_login(client, {"X-Forwarded-For": "9.9.9.1"}).status_code == 401
    assert attempt_login(client, {"X-Forwarded-For": "9.9.9.1"}).status_code == 429
    assert attempt_login(client, {"X-Forwarded-For": "9.9.9.2"}).status_code == 401