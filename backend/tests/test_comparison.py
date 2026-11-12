import json
import uuid

from sqlalchemy import update

from app.models import AnalysisRun
from app.samples.catalog import read_sample
from ai_support import analyzed, runs_url
from support import API, encode_document, post_import


def compare_url(environment_id, base_id, target_id):
    return f"{API}/environments/{environment_id}/comparison?base_run_id={base_id}&target_run_id={target_id}"


def run_variant(client, headers, environment_id, mutate):
    document = json.loads(read_sample("acme-prod"))
    mutate(document)
    imported = post_import(client, headers, environment_id, encode_document(document), "variant.json")
    assert imported.status_code == 201
    run = client.post(runs_url(environment_id), json={"import_id": imported.json()["id"]}, headers=headers)
    assert run.status_code == 201
    return run.json()


def remove_alice_policy(document):
    for identity in document["identities"]:
        if identity["name"] == "alice-admin":
            identity["policy_ids"] = []


def delete_alice(document):
    document["identities"] = [
        identity for identity in document["identities"] if identity["name"] != "alice-admin"
    ]


def remove_deploy_trust(document):
    for identity in document["identities"]:
        if identity["name"] == "deploy-role":
            del identity["trust_policy"]


def compare(client, headers, environment_id, base_id, target_id):
    response = client.get(compare_url(environment_id, base_id, target_id), headers=headers)
    assert response.status_code == 200
    return response.json()


def with_status(items, status):
    return [item for item in items if item["status"] == status]


def test_rerun_of_the_same_import_has_no_differences(client, auth_headers):
    environment, first = analyzed(client, auth_headers)
    second = client.post(runs_url(environment["id"]), headers=auth_headers).json()
    result = compare(client, auth_headers, environment["id"], first["id"], second["id"])
    assert result["finding_counts"] == {
        "new": 0,
        "persisting": 6,
        "no_longer_detected": 0,
        "not_comparable": 0,
    }
    assert result["path_counts"]["persisting"] == 9
    assert result["path_counts"]["new"] == result["path_counts"]["no_longer_detected"] == 0
    assert result["base"]["finding_count"] == result["target"]["finding_count"] == 6
    assert any("does not mean the environment is secure" in item for item in result["caveats"])


def test_remediation_is_reported_as_no_longer_detected_not_resolved(client, auth_headers):
    environment, first = analyzed(client, auth_headers)
    fixed = run_variant(client, auth_headers, environment["id"], remove_alice_policy)
    result = compare(client, auth_headers, environment["id"], first["id"], fixed["id"])
    assert result["finding_counts"] == {
        "new": 0,
        "persisting": 5,
        "no_longer_detected": 1,
        "not_comparable": 0,
    }
    gone = with_status(result["findings"], "no_longer_detected")[0]
    assert gone["rule_id"] == "CT-IAM-001"
    assert gone["base_score"] == 80 and gone["target_score"] is None
    assert "still in the target import" in gone["reason"]
    assert result["base"]["high_risk_finding_count"] == 2
    assert result["target"]["high_risk_finding_count"] == 1
    assert result["path_counts"]["persisting"] == 9
    assert "resolved" not in json.dumps(result)


def test_deleted_identity_makes_its_finding_not_comparable(client, auth_headers):
    environment, first = analyzed(client, auth_headers)
    changed = run_variant(client, auth_headers, environment["id"], delete_alice)
    result = compare(client, auth_headers, environment["id"], first["id"], changed["id"])
    assert result["finding_counts"]["not_comparable"] == 1
    assert result["finding_counts"]["no_longer_detected"] == 0
    item = with_status(result["findings"], "not_comparable")[0]
    assert item["rule_id"] == "CT-IAM-001"
    assert "no longer exists" in item["reason"]
    assert any("cannot be compared" in caveat for caveat in result["caveats"])


def test_removed_trust_policy_removes_only_dependent_paths(client, auth_headers):
    environment, first = analyzed(client, auth_headers)
    changed = run_variant(client, auth_headers, environment["id"], remove_deploy_trust)
    result = compare(client, auth_headers, environment["id"], first["id"], changed["id"])
    assert result["path_counts"] == {
        "new": 0,
        "persisting": 5,
        "no_longer_detected": 4,
        "not_comparable": 0,
    }
    assert result["finding_counts"]["persisting"] == 6
    assert result["base"]["attack_path_count"] == 9
    assert result["target"]["attack_path_count"] == 5


def test_reversing_the_comparison_reports_the_finding_as_new(client, auth_headers):
    environment, original = analyzed(client, auth_headers)
    fixed = run_variant(client, auth_headers, environment["id"], remove_alice_policy)
    result = compare(client, auth_headers, environment["id"], fixed["id"], original["id"])
    assert result["finding_counts"]["new"] == 1
    assert with_status(result["findings"], "new")[0]["rule_id"] == "CT-IAM-001"
    assert result["findings"][0]["status"] == "new"


def test_engine_version_and_incomplete_paths_add_caveats(client, db_session, auth_headers):
    environment, first = analyzed(client, auth_headers)
    second = client.post(runs_url(environment["id"]), headers=auth_headers).json()
    db_session.execute(
        update(AnalysisRun)
        .where(AnalysisRun.id == uuid.UUID(first["id"]))
        .values(analysis_version="0.9.0")
    )
    db_session.execute(
        update(AnalysisRun)
        .where(AnalysisRun.id == uuid.UUID(second["id"]))
        .values(paths_incomplete=True)
    )
    db_session.commit()
    result = compare(client, auth_headers, environment["id"], first["id"], second["id"])
    assert any("engine versions" in caveat for caveat in result["caveats"])
    assert any("reached a limit" in caveat for caveat in result["caveats"])
    assert result["base"]["analysis_version"] == "0.9.0"


def test_comparing_a_run_with_itself_is_rejected(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    response = client.get(compare_url(environment["id"], run["id"], run["id"]), headers=auth_headers)
    assert response.status_code == 422


def test_failed_runs_cannot_be_compared(client, auth_headers, monkeypatch):
    environment, run = analyzed(client, auth_headers)

    def explode(snapshot):
        raise RuntimeError("internal detail")

    monkeypatch.setattr("app.services.analysis.analyze", explode)
    assert client.post(runs_url(environment["id"]), headers=auth_headers).status_code == 500
    runs = client.get(runs_url(environment["id"]), headers=auth_headers).json()
    failed = next(item for item in runs if item["status"] == "failed")
    response = client.get(compare_url(environment["id"], run["id"], failed["id"]), headers=auth_headers)
    assert response.status_code == 409


def test_comparison_access_control(client, auth_headers, other_auth_headers):
    environment, run = analyzed(client, auth_headers)
    second = client.post(runs_url(environment["id"]), headers=auth_headers).json()
    url = compare_url(environment["id"], run["id"], second["id"])
    assert client.get(url).status_code == 401
    assert client.get(url, headers=other_auth_headers).status_code == 404

    other_environment, other_run = analyzed(client, auth_headers, "other")
    crossed = compare_url(environment["id"], run["id"], other_run["id"])
    assert client.get(crossed, headers=auth_headers).status_code == 404