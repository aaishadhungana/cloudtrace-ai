import copy
import json
import uuid

from sqlalchemy import func, select

from app.models import PermissionRelationship
from app.samples.catalog import read_sample
from support import API, create_environment, encode_document, post_import


def runs_url(environment_id: str) -> str:
    return f"{API}/environments/{environment_id}/analysis-runs"


def import_sample(client, headers, environment_id, name="acme-prod"):
    response = post_import(client, headers, environment_id, read_sample(name), f"{name}.json")
    assert response.status_code == 201
    return response.json()


def start_run(client, headers, environment_id, import_id=None):
    payload = {"import_id": import_id} if import_id else None
    return client.post(runs_url(environment_id), json=payload, headers=headers)


def analyzed(client, headers, name="prod"):
    environment = create_environment(client, headers, name)
    import_sample(client, headers, environment["id"])
    response = start_run(client, headers, environment["id"])
    assert response.status_code == 201
    return environment, response.json()


def findings_of(client, headers, environment_id, run_id, query=""):
    response = client.get(f"{runs_url(environment_id)}/{run_id}/findings{query}", headers=headers)
    assert response.status_code == 200
    return response.json()


def identity_named(client, headers, environment_id, run_id, name):
    response = client.get(f"{runs_url(environment_id)}/{run_id}/identities", headers=headers)
    assert response.status_code == 200
    return next(item for item in response.json() if item["name"] == name)


def test_run_requires_an_import(client, auth_headers):
    environment = create_environment(client, auth_headers)
    assert start_run(client, auth_headers, environment["id"]).status_code == 409


def test_run_on_production_sample_stores_findings(client, db_session, auth_headers):
    environment, run = analyzed(client, auth_headers)
    assert run["status"] == "completed"
    assert run["finding_count"] == 6
    assert run["analysis_version"] == "1.0.0"
    assert run["severity_counts"] == {"critical": 1, "high": 1, "medium": 3, "low": 1, "info": 0}
    stored = db_session.scalar(
        select(func.count())
        .select_from(PermissionRelationship)
        .where(PermissionRelationship.analysis_run_id == uuid.UUID(run["id"]))
    )
    assert stored and stored > 0


def test_run_detail_lists_limitations_and_source(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    response = client.get(f"{runs_url(environment['id'])}/{run['id']}", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["import_source"] == "acme-prod.json"
    assert body["limitations"]


def test_findings_are_sorted_filtered_and_counted(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    page = findings_of(client, auth_headers, environment["id"], run["id"])
    assert page["total"] == 6
    scores = [item["risk_score"] for item in page["items"]]
    assert scores == [80, 65, 55, 54, 45, 33]

    critical = findings_of(client, auth_headers, environment["id"], run["id"], "?severity=critical")
    assert [item["rule_id"] for item in critical["items"]] == ["CT-IAM-001"]

    by_rule = findings_of(client, auth_headers, environment["id"], run["id"], "?rule_id=CT-IAM-005")
    assert by_rule["total"] == 1

    ascending = findings_of(client, auth_headers, environment["id"], run["id"], "?sort=score_asc")
    assert ascending["items"][0]["rule_id"] == "CT-IAM-010"


def test_invalid_filters_are_rejected(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    base = f"{runs_url(environment['id'])}/{run['id']}/findings"
    assert client.get(f"{base}?severity=bogus", headers=auth_headers).status_code == 422
    assert client.get(f"{base}?rule_id=nope", headers=auth_headers).status_code == 422
    assert client.get(f"{base}?limit=0", headers=auth_headers).status_code == 422


def test_finding_detail_explains_the_score(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    page = findings_of(client, auth_headers, environment["id"], run["id"], "?severity=critical")
    finding_id = page["items"][0]["id"]
    response = client.get(
        f"{runs_url(environment['id'])}/{run['id']}/findings/{finding_id}", headers=auth_headers
    )
    assert response.status_code == 200
    body = response.json()
    assert body["rule_id"] == "CT-IAM-001"
    assert body["identity_name"] == "alice-admin"
    assert body["evidence"] and body["explanation"] and body["remediation"]
    assert sum(factor["points"] for factor in body["risk_factors"]) == body["raw_score"] == 80


def test_identity_explorer_reflects_findings_and_reach(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    args = (client, auth_headers, environment["id"], run["id"])
    alice = identity_named(*args, "alice-admin")
    assert alice["finding_count"] == 1
    assert alice["max_risk_score"] == 80
    assert alice["risk_level"] == "critical"
    carol = identity_named(*args, "carol-analyst")
    assert carol["finding_count"] == 1
    assert carol["risk_level"] == "low"
    runtime = identity_named(*args, "app-runtime-role")
    assert runtime["finding_count"] == 0
    assert runtime["risk_level"] is None
    assert runtime["reachable_target_count"] == 2
    assert runtime["sensitive_target_count"] == 2


def test_identity_detail_shows_deny_and_policies(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    carol = identity_named(client, auth_headers, environment["id"], run["id"], "carol-analyst")
    response = client.get(
        f"{runs_url(environment['id'])}/{run['id']}/identities/{carol['id']}",
        headers=auth_headers,
    )
    assert response.status_code == 200
    body = response.json()
    assert {policy["name"] for policy in body["policies"]} == {
        "AnalystReadOnly",
        "DenyCustomerData",
    }
    denied = [entry for entry in body["access"] if entry["target_name"] == "acme-customer-data"]
    assert denied and all(entry["decision"] == "explicitly_denied" for entry in denied)
    assert denied[0]["statements"]
    assert [item["rule_id"] for item in body["findings"]] == ["CT-IAM-010"]


def test_analysis_is_repeatable(client, auth_headers):
    environment, first = analyzed(client, auth_headers)
    second = start_run(client, auth_headers, environment["id"]).json()
    assert second["id"] != first["id"]

    def snapshot(run):
        page = findings_of(client, auth_headers, environment["id"], run["id"])
        return [(item["rule_id"], item["risk_score"], item["title"]) for item in page["items"]]

    assert snapshot(first) == snapshot(second)


def test_remediation_import_produces_a_fresh_analysis(client, auth_headers):
    environment, first = analyzed(client, auth_headers)
    fixed = json.loads(read_sample("acme-prod"))
    for identity in fixed["identities"]:
        if identity["name"] == "alice-admin":
            identity["policy_ids"] = []
    second_import = post_import(
        client, auth_headers, environment["id"], encode_document(fixed), "fixed.json"
    )
    assert second_import.status_code == 201
    second = start_run(client, auth_headers, environment["id"], second_import.json()["id"]).json()
    assert second["finding_count"] == 5
    page = findings_of(client, auth_headers, environment["id"], second["id"])
    assert "CT-IAM-001" not in {item["rule_id"] for item in page["items"]}
    runs = client.get(runs_url(environment["id"]), headers=auth_headers).json()
    assert {run["id"] for run in runs} == {first["id"], second["id"]}


def test_development_sample_has_no_findings(client, auth_headers):
    environment = create_environment(client, auth_headers, "dev")
    import_sample(client, auth_headers, environment["id"], "acme-dev")
    run = start_run(client, auth_headers, environment["id"]).json()
    assert run["finding_count"] == 0
    assert findings_of(client, auth_headers, environment["id"], run["id"])["total"] == 0


def test_run_rejects_import_from_another_environment(client, auth_headers):
    first = create_environment(client, auth_headers, "a")
    second = create_environment(client, auth_headers, "b")
    imported = import_sample(client, auth_headers, first["id"])
    response = start_run(client, auth_headers, second["id"], imported["id"])
    assert response.status_code == 404


def test_failed_analysis_is_recorded_and_hides_internals(client, auth_headers, monkeypatch):
    environment = create_environment(client, auth_headers)
    import_sample(client, auth_headers, environment["id"])

    def explode(snapshot):
        raise RuntimeError("internal detail")

    monkeypatch.setattr("app.services.analysis.analyze", explode)
    response = start_run(client, auth_headers, environment["id"])
    assert response.status_code == 500
    assert response.json() == {"detail": "Analysis failed"}
    runs = client.get(runs_url(environment["id"]), headers=auth_headers).json()
    assert [run["status"] for run in runs] == ["failed"]


def test_analysis_endpoints_require_authentication(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    base = runs_url(environment["id"])
    assert client.post(base).status_code == 401
    assert client.get(base).status_code == 401
    assert client.get(f"{base}/{run['id']}").status_code == 401
    assert client.get(f"{API}/rules").status_code == 401


def test_other_users_cannot_read_or_start_analysis(client, auth_headers, other_auth_headers):
    environment, run = analyzed(client, auth_headers)
    finding_id = findings_of(client, auth_headers, environment["id"], run["id"])["items"][0]["id"]
    identity_id = identity_named(client, auth_headers, environment["id"], run["id"], "alice-admin")["id"]
    base = f"{runs_url(environment['id'])}/{run['id']}"
    attempts = [
        client.post(runs_url(environment["id"]), headers=other_auth_headers),
        client.get(runs_url(environment["id"]), headers=other_auth_headers),
        client.get(base, headers=other_auth_headers),
        client.get(f"{base}/findings", headers=other_auth_headers),
        client.get(f"{base}/findings/{finding_id}", headers=other_auth_headers),
        client.get(f"{base}/identities", headers=other_auth_headers),
        client.get(f"{base}/identities/{identity_id}", headers=other_auth_headers),
    ]
    assert [attempt.status_code for attempt in attempts] == [404] * 7


def test_run_id_from_another_environment_is_not_found(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    other = create_environment(client, auth_headers, "other")
    assert client.get(f"{runs_url(other['id'])}/{run['id']}", headers=auth_headers).status_code == 404


def test_finding_and_identity_ids_are_scoped_to_their_run(client, auth_headers):
    environment, first = analyzed(client, auth_headers)
    second = start_run(client, auth_headers, environment["id"]).json()
    finding_id = findings_of(client, auth_headers, environment["id"], first["id"])["items"][0]["id"]
    response = client.get(
        f"{runs_url(environment['id'])}/{second['id']}/findings/{finding_id}", headers=auth_headers
    )
    assert response.status_code == 404


def test_rule_catalog_lists_every_rule(client, auth_headers):
    response = client.get(f"{API}/rules", headers=auth_headers)
    assert response.status_code == 200
    assert [rule["rule_id"] for rule in response.json()] == [
        f"CT-IAM-{number:03d}" for number in range(1, 11)
    ]