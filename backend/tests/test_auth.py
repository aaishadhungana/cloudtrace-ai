import uuid
from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import get_settings
from support import API, TEST_PASSWORD, register_and_login, unique_email


def make_token(subject: str, secret: str, expires_in: timedelta) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": subject, "iat": now, "exp": now + expires_in}
    return jwt.encode(claims, secret, algorithm="HS256")


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_register_returns_user_without_secrets(client):
    email = unique_email()
    response = client.post(
        f"{API}/auth/register", json={"email": email, "password": TEST_PASSWORD}
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == email
    assert "password" not in body
    assert "password_hash" not in body


def test_register_rejects_duplicate_email_case_insensitively(client):
    email = unique_email()
    register_and_login(client, email)
    response = client.post(
        f"{API}/auth/register", json={"email": email.upper(), "password": TEST_PASSWORD}
    )
    assert response.status_code == 409


def test_register_rejects_short_password(client):
    response = client.post(
        f"{API}/auth/register", json={"email": unique_email(), "password": "short"}
    )
    assert response.status_code == 422


def test_register_rejects_invalid_email_and_extra_fields(client):
    invalid_email = client.post(
        f"{API}/auth/register", json={"email": "not-an-email", "password": TEST_PASSWORD}
    )
    extra_field = client.post(
        f"{API}/auth/register",
        json={"email": unique_email(), "password": TEST_PASSWORD, "is_admin": True},
    )
    assert invalid_email.status_code == 422
    assert extra_field.status_code == 422


def test_login_failures_do_not_reveal_which_part_was_wrong(client):
    email = unique_email()
    register_and_login(client, email)
    wrong_password = client.post(
        f"{API}/auth/login", json={"email": email, "password": "wrong-password-value"}
    )
    unknown_email = client.post(
        f"{API}/auth/login", json={"email": unique_email(), "password": TEST_PASSWORD}
    )
    assert wrong_password.status_code == 401
    assert unknown_email.status_code == 401
    assert wrong_password.json() == unknown_email.json()


def test_me_returns_current_user(client):
    email = unique_email()
    headers = register_and_login(client, email)
    response = client.get(f"{API}/auth/me", headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == email


def test_protected_endpoint_requires_token(client):
    response = client.get(f"{API}/auth/me")
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


def test_malformed_token_is_rejected(client):
    response = client.get(f"{API}/auth/me", headers=bearer("not.a.token"))
    assert response.status_code == 401


def test_expired_token_is_rejected(client):
    email = unique_email()
    headers = register_and_login(client, email)
    user_id = client.get(f"{API}/auth/me", headers=headers).json()["id"]
    token = make_token(user_id, get_settings().jwt_secret_key, timedelta(minutes=-5))
    assert client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401


def test_token_signed_with_another_secret_is_rejected(client):
    headers = register_and_login(client)
    user_id = client.get(f"{API}/auth/me", headers=headers).json()["id"]
    token = make_token(user_id, "x" * 48, timedelta(minutes=5))
    assert client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401


def test_unsigned_token_is_rejected(client):
    headers = register_and_login(client)
    user_id = client.get(f"{API}/auth/me", headers=headers).json()["id"]
    now = datetime.now(timezone.utc)
    claims = {"sub": user_id, "iat": now, "exp": now + timedelta(minutes=5)}
    token = jwt.encode(claims, None, algorithm="none")
    assert client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401


def test_token_for_unknown_user_is_rejected(client):
    token = make_token(str(uuid.uuid4()), get_settings().jwt_secret_key, timedelta(minutes=5))
    assert client.get(f"{API}/auth/me", headers=bearer(token)).status_code == 401