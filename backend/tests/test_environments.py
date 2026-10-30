import uuid

from support import API, create_environment


def test_environment_crud_flow(client, auth_headers):
    created = create_environment(client, auth_headers, "prod")
    assert created["cloud_provider"] == "aws"

    listed = client.get(f"{API}/environments", headers=auth_headers).json()
    assert [item["id"] for item in listed] == [created["id"]]

    fetched = client.get(f"{API}/environments/{created['id']}", headers=auth_headers)
    assert fetched.status_code == 200

    updated = client.patch(
        f"{API}/environments/{created['id']}",
        json={"name": "production", "description": "Main account"},
        headers=auth_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "production"
    assert updated.json()["description"] == "Main account"

    deleted = client.delete(f"{API}/environments/{created['id']}", headers=auth_headers)
    assert deleted.status_code == 204
    missing = client.get(f"{API}/environments/{created['id']}", headers=auth_headers)
    assert missing.status_code == 404


def test_environment_endpoints_require_authentication(client):
    assert client.get(f"{API}/environments").status_code == 401
    assert client.post(f"{API}/environments", json={"name": "x"}).status_code == 401
    assert client.get(f"{API}/environments/{uuid.uuid4()}").status_code == 401


def test_duplicate_environment_name_is_rejected_per_owner(client, auth_headers, other_auth_headers):
    create_environment(client, auth_headers, "prod")
    duplicate = client.post(f"{API}/environments", json={"name": "prod"}, headers=auth_headers)
    assert duplicate.status_code == 409
    other_owner = client.post(f"{API}/environments", json={"name": "prod"}, headers=other_auth_headers)
    assert other_owner.status_code == 201


def test_user_cannot_access_another_users_environment(client, auth_headers, other_auth_headers):
    owned = create_environment(client, auth_headers, "private")
    url = f"{API}/environments/{owned['id']}"
    assert client.get(url, headers=other_auth_headers).status_code == 404
    assert client.patch(url, json={"name": "hijacked"}, headers=other_auth_headers).status_code == 404
    assert client.delete(url, headers=other_auth_headers).status_code == 404
    assert client.get(f"{API}/environments", headers=other_auth_headers).json() == []
    still_there = client.get(url, headers=auth_headers)
    assert still_there.status_code == 200
    assert still_there.json()["name"] == "private"


def test_environment_validation(client, auth_headers):
    empty_name = client.post(f"{API}/environments", json={"name": "  "}, headers=auth_headers)
    extra_field = client.post(
        f"{API}/environments", json={"name": "x", "owner_id": str(uuid.uuid4())}, headers=auth_headers
    )
    bad_provider = client.post(
        f"{API}/environments", json={"name": "x", "cloud_provider": "gcp"}, headers=auth_headers
    )
    assert empty_name.status_code == 422
    assert extra_field.status_code == 422
    assert bad_provider.status_code == 422


def test_patch_rejects_null_name(client, auth_headers):
    created = create_environment(client, auth_headers)
    response = client.patch(
        f"{API}/environments/{created['id']}", json={"name": None}, headers=auth_headers
    )
    assert response.status_code == 422