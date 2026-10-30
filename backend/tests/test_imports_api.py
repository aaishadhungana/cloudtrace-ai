import uuid

from sqlalchemy import func, select

from app.core.config import get_settings
from app.models import Identity, ImportRecord, Policy, Resource
from app.samples.catalog import read_sample
from support import (
    API,
    create_environment,
    encode_document,
    minimal_document,
    post_import,
)


def test_valid_sample_import_is_stored(client, db_session, auth_headers):
    environment = create_environment(client, auth_headers)
    response = post_import(
        client, auth_headers, environment["id"], read_sample("acme-prod"), "acme-prod.json"
    )
    assert response.status_code == 201
    body = response.json()
    assert body["validation_status"] == "valid"
    assert body["schema_version"] == "1.0"
    assert body["import_source"] == "acme-prod.json"
    assert body["sanitized_metadata"]["identity_count"] == 9
    assert body["sanitized_metadata"]["resource_count"] == 6
    assert body["sanitized_metadata"]["policy_count"] == 8
    assert body["sanitized_metadata"]["sensitive_resource_count"] == 3

    import_id = uuid.UUID(body["id"])
    for model, expected in ((Identity, 9), (Resource, 6), (Policy, 8)):
        count = db_session.scalar(
            select(func.count()).select_from(model).where(model.import_id == import_id)
        )
        assert count == expected


def test_imports_are_listed_newest_first(client, auth_headers):
    environment = create_environment(client, auth_headers)
    post_import(client, auth_headers, environment["id"], read_sample("acme-dev"))
    listed = client.get(f"{API}/environments/{environment['id']}/imports", headers=auth_headers)
    assert listed.status_code == 200
    assert len(listed.json()) == 1


def test_import_requires_authentication(client):
    response = client.post(
        f"{API}/environments/{uuid.uuid4()}/imports",
        content=b"{}",
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 401


def test_user_cannot_import_into_or_list_another_users_environment(
    client, db_session, auth_headers, other_auth_headers
):
    environment = create_environment(client, auth_headers)
    attempt = post_import(client, other_auth_headers, environment["id"], read_sample("acme-dev"))
    listing = client.get(
        f"{API}/environments/{environment['id']}/imports", headers=other_auth_headers
    )
    assert attempt.status_code == 404
    assert listing.status_code == 404
    assert db_session.scalar(select(func.count()).select_from(ImportRecord)) == 0


def test_invalid_import_is_rejected_with_issues_and_not_stored(client, db_session, auth_headers):
    environment = create_environment(client, auth_headers)
    response = post_import(client, auth_headers, environment["id"], b"{}")
    assert response.status_code == 422
    detail = response.json()["detail"]
    assert detail["message"] == "Import validation failed"
    assert detail["issues"]
    assert db_session.scalar(select(func.count()).select_from(ImportRecord)) == 0


def test_semantically_invalid_import_is_rejected(client, auth_headers):
    document = minimal_document()
    document["identities"][0]["policy_ids"] = ["missing-policy"]
    environment = create_environment(client, auth_headers)
    response = post_import(client, auth_headers, environment["id"], encode_document(document))
    assert response.status_code == 422
    messages = [issue["message"] for issue in response.json()["detail"]["issues"]]
    assert any("unknown policy" in message for message in messages)


def test_oversized_import_is_rejected(client, auth_headers, monkeypatch):
    monkeypatch.setattr(get_settings(), "import_max_bytes", 50)
    environment = create_environment(client, auth_headers)
    response = post_import(client, auth_headers, environment["id"], b"x" * 200)
    assert response.status_code == 413


def test_non_json_content_type_is_rejected(client, auth_headers):
    environment = create_environment(client, auth_headers)
    response = client.post(
        f"{API}/environments/{environment['id']}/imports",
        content=b"{}",
        headers={**auth_headers, "Content-Type": "text/plain"},
    )
    assert response.status_code == 415


def test_source_label_cannot_contain_path_characters(client, auth_headers):
    environment = create_environment(client, auth_headers)
    response = post_import(
        client, auth_headers, environment["id"], read_sample("acme-dev"), "../../etc/passwd"
    )
    assert response.status_code == 422