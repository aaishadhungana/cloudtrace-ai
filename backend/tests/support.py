import json
import uuid
from typing import Any

from fastapi.testclient import TestClient

TEST_PASSWORD = "correct-horse-battery"
API = "/api/v1"


def unique_email() -> str:
    return f"user-{uuid.uuid4().hex[:12]}@example.com"


def register_and_login(client: TestClient, email: str | None = None) -> dict[str, str]:
    address = email or unique_email()
    registered = client.post(
        f"{API}/auth/register", json={"email": address, "password": TEST_PASSWORD}
    )
    assert registered.status_code == 201
    login = client.post(f"{API}/auth/login", json={"email": address, "password": TEST_PASSWORD})
    assert login.status_code == 200
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def create_environment(
    client: TestClient, headers: dict[str, str], name: str = "prod"
) -> dict[str, Any]:
    response = client.post(f"{API}/environments", json={"name": name}, headers=headers)
    assert response.status_code == 201
    return response.json()


def minimal_document() -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "identities": [
            {
                "arn": "arn:aws:iam::111122223333:user/alice",
                "name": "alice",
                "type": "iam_user",
                "policy_ids": ["read-reports"],
            }
        ],
        "resources": [
            {
                "arn": "arn:aws:s3:::reports",
                "name": "reports",
                "type": "storage_bucket",
                "sensitive": False,
            }
        ],
        "policies": [
            {
                "id": "read-reports",
                "name": "ReadReports",
                "statements": [
                    {
                        "effect": "Allow",
                        "actions": ["s3:GetObject"],
                        "resources": ["arn:aws:s3:::reports/*"],
                    }
                ],
            }
        ],
    }


def encode_document(document: dict[str, Any]) -> bytes:
    return json.dumps(document).encode()


def post_import(
    client: TestClient,
    headers: dict[str, str],
    environment_id: str,
    body: bytes,
    source: str = "test.json",
):
    return client.post(
        f"{API}/environments/{environment_id}/imports",
        params={"source": source},
        content=body,
        headers={**headers, "Content-Type": "application/json"},
    )