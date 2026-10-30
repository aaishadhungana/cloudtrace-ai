import json

from app.ingest.pipeline import process_import
from app.samples.catalog import read_sample
from support import API


def test_sample_catalog_requires_authentication(client):
    assert client.get(f"{API}/samples").status_code == 401
    assert client.get(f"{API}/samples/acme-prod").status_code == 401


def test_sample_catalog_lists_bundled_samples(client, auth_headers):
    response = client.get(f"{API}/samples", headers=auth_headers)
    assert response.status_code == 200
    assert {item["name"] for item in response.json()} == {"acme-prod", "acme-dev"}


def test_sample_document_is_valid_json_that_passes_import(client, auth_headers):
    response = client.get(f"{API}/samples/acme-prod", headers=auth_headers)
    assert response.status_code == 200
    assert json.loads(response.content)["schema_version"] == "1.0"
    assert process_import(response.content).metadata["identity_count"] == 9


def test_unknown_sample_returns_404(client, auth_headers):
    assert client.get(f"{API}/samples/missing", headers=auth_headers).status_code == 404


def test_path_traversal_names_never_reach_the_filesystem(client, auth_headers):
    response = client.get(f"{API}/samples/..%2F..%2Fetc%2Fpasswd", headers=auth_headers)
    assert response.status_code in {404, 422}
    assert read_sample("../conftest") is None
    assert read_sample("acme_prod.json") is None