import json
import uuid

from app.samples.catalog import read_sample
from support import API, create_environment, encode_document, post_import


def runs_url(environment_id):
    return f"{API}/environments/{environment_id}/analysis-runs"


def paths_url(environment_id, run_id):
    return f"{runs_url(environment_id)}/{run_id}/attack-paths"


def start_run(client, headers, environment_id, import_id=None):
    payload = {"import_id": import_id} if import_id else None
    return client.post(runs_url(environment_id), json=payload, headers=headers)


def analyzed(client, headers, name="prod", sample="acme-prod"):
    environment = create_environment(client, headers, name)
    imported = post_import(client, headers, environment["id"], read_sample(sample), f"{sample}.json")
    assert imported.status_code == 201
    run = start_run(client, headers, environment["id"])
    assert run.status_code == 201
    return environment, run.json()


def list_paths(client, headers, environment_id, run_id, query=""):
    response = client.get(f"{paths_url(environment_id, run_id)}{query}", headers=headers)
    assert response.status_code == 200
    return response.json()


def test_run_records_attack_path_counts(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    assert run["attack_path_count"] == 9
    assert run["paths_incomplete"] is False
    assert run["analysis_version"] == "1.1.0"


def test_paths_are_sorted_and_filterable(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    page = list_paths(client, auth_headers, environment["id"], run["id"])
    assert page["total"] == 9
    assert [item["risk_score"] for item in page["items"]] == [65, 35, 35, 25, 25, 25, 20, 20, 20]
    assert page["items"][0]["severity"] == "high"

    supported = list_paths(
        client, auth_headers, environment["id"], run["id"], "?classification=supported"
    )
    assert supported["total"] == 3
    assert {item["classification"] for item in supported["items"]} == {"supported"}

    strong = list_paths(client, auth_headers, environment["id"], run["id"], "?min_score=30")
    assert strong["total"] == 3

    ascending = list_paths(client, auth_headers, environment["id"], run["id"], "?sort=score_asc")
    assert ascending["items"][0]["risk_score"] == 20


def test_invalid_path_filters_are_rejected(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    base = paths_url(environment["id"], run["id"])
    assert client.get(f"{base}?classification=bogus", headers=auth_headers).status_code == 422
    assert client.get(f"{base}?min_score=101", headers=auth_headers).status_code == 422
    assert client.get(f"{base}?limit=0", headers=auth_headers).status_code == 422


def test_attack_path_detail_has_graph_data_and_evidence(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    top = list_paths(client, auth_headers, environment["id"], run["id"])["items"][0]
    response = client.get(
        f"{paths_url(environment['id'], run['id'])}/{top['id']}", headers=auth_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["start_identity_name"] == "bob-developer"
    assert body["target_resource_name"] == "acme-customer-data"
    assert body["classification"] == "supported"
    assert [node["position"] for node in body["nodes"]] == ["start", "pivot", "target"]
    assert all(node["id"] for node in body["nodes"])
    assert [edge["relationship"] for edge in body["edges"]] == ["can_assume", "can_write"]
    assert len(body["evidence"]) == 2 and all(item["statements"] for item in body["evidence"])
    assert sum(factor["points"] for factor in body["risk_factors"]) == body["raw_score"] == 65
    assert body["summary"].startswith("bob-developer can assume deploy-role.")


def test_potential_paths_explain_their_assumptions(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    potential = list_paths(
        client, auth_headers, environment["id"], run["id"], "?classification=potential"
    )
    assert potential["total"] == 6
    detail = client.get(
        f"{paths_url(environment['id'], run['id'])}/{potential['items'][0]['id']}",
        headers=auth_headers,
    ).json()
    assert any(edge["assumption"] for edge in detail["edges"])


def test_attack_path_endpoints_require_authentication(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    assert client.get(paths_url(environment["id"], run["id"])).status_code == 401


def test_other_users_cannot_read_attack_paths(client, auth_headers, other_auth_headers):
    environment, run = analyzed(client, auth_headers)
    path_id = list_paths(client, auth_headers, environment["id"], run["id"])["items"][0]["id"]
    base = paths_url(environment["id"], run["id"])
    assert client.get(base, headers=other_auth_headers).status_code == 404
    assert client.get(f"{base}/{path_id}", headers=other_auth_headers).status_code == 404


def test_path_ids_are_scoped_to_their_run(client, auth_headers):
    environment, first = analyzed(client, auth_headers)
    second = start_run(client, auth_headers, environment["id"]).json()
    path_id = list_paths(client, auth_headers, environment["id"], first["id"])["items"][0]["id"]
    response = client.get(
        f"{paths_url(environment['id'], second['id'])}/{path_id}", headers=auth_headers
    )
    assert response.status_code == 404
    assert client.get(
        f"{paths_url(environment['id'], first['id'])}/{uuid.uuid4()}", headers=auth_headers
    ).status_code == 404


def test_development_environment_has_no_attack_paths(client, auth_headers):
    environment, run = analyzed(client, auth_headers, "dev", "acme-dev")
    assert run["attack_path_count"] == 0
    assert list_paths(client, auth_headers, environment["id"], run["id"])["total"] == 0


def test_remediated_import_produces_fewer_paths(client, auth_headers):
    environment, first = analyzed(client, auth_headers)
    fixed = json.loads(read_sample("acme-prod"))
    for identity in fixed["identities"]:
        if identity["name"] == "deploy-role":
            del identity["trust_policy"]
    second_import = post_import(
        client, auth_headers, environment["id"], encode_document(fixed), "fixed.json"
    )
    second = start_run(client, auth_headers, environment["id"], second_import.json()["id"]).json()
    assert second["attack_path_count"] == 5
    page = list_paths(client, auth_headers, environment["id"], second["id"])
    assert {item["start_identity_name"] for item in page["items"]} == {
        "deploy-role",
        "app-service",
    }