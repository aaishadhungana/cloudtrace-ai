import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import update

from app.models import AnalysisRun
from app.models.enums import AnalysisStatus
from ai_support import analyzed, runs_url
from support import API

EMPTY = {
    "environment_count": 0,
    "analyzed_environment_count": 0,
    "identity_count": 0,
    "sensitive_resource_count": 0,
    "open_finding_count": 0,
    "critical_high_finding_count": 0,
    "attack_path_count": 0,
    "recent_runs": [],
    "top_findings": [],
}


def dashboard(client, headers):
    response = client.get(f"{API}/dashboard", headers=headers)
    assert response.status_code == 200
    return response.json()


def test_dashboard_is_empty_for_a_new_user(client, auth_headers):
    assert dashboard(client, auth_headers) == EMPTY


def test_dashboard_summarizes_the_latest_completed_runs(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    body = dashboard(client, auth_headers)
    assert body["environment_count"] == 1
    assert body["analyzed_environment_count"] == 1
    assert body["identity_count"] == 9
    assert body["sensitive_resource_count"] == 3
    assert body["open_finding_count"] == 6
    assert body["critical_high_finding_count"] == 2
    assert body["attack_path_count"] == 9
    assert len(body["recent_runs"]) == 1
    assert body["recent_runs"][0]["environment_name"] == "prod"
    assert body["top_findings"][0]["risk_score"] == 80
    assert body["top_findings"][0]["title"] == "alice-admin has wildcard administrative permissions"
    assert body["top_findings"][0]["environment_name"] == "prod"


def test_dashboard_combines_environments_and_ignores_older_runs(client, auth_headers):
    prod, _ = analyzed(client, auth_headers)
    analyzed(client, auth_headers, "dev", "acme-dev")
    client.post(runs_url(prod["id"]), headers=auth_headers)
    body = dashboard(client, auth_headers)
    assert body["environment_count"] == 2
    assert body["analyzed_environment_count"] == 2
    assert body["identity_count"] == 11
    assert body["sensitive_resource_count"] == 3
    assert body["open_finding_count"] == 6
    assert body["attack_path_count"] == 9
    assert len(body["recent_runs"]) == 3


def test_failed_latest_run_does_not_replace_the_last_completed_one(
    client, db_session, auth_headers, monkeypatch
):
    environment, completed = analyzed(client, auth_headers)

    def explode(snapshot):
        raise RuntimeError("internal detail")

    monkeypatch.setattr("app.services.analysis.analyze", explode)
    assert client.post(runs_url(environment["id"]), headers=auth_headers).status_code == 500

    db_session.execute(
        update(AnalysisRun)
        .where(
            AnalysisRun.environment_id == uuid.UUID(environment["id"]),
            AnalysisRun.status == AnalysisStatus.FAILED,
        )
        .values(started_at=datetime.now(timezone.utc) + timedelta(minutes=1))
    )
    db_session.commit()

    body = dashboard(client, auth_headers)
    assert body["open_finding_count"] == 6
    assert body["attack_path_count"] == 9
    assert body["recent_runs"][0]["status"] == "failed"
    assert body["recent_runs"][1]["run_id"] == completed["id"]


def test_dashboard_is_scoped_to_the_user(client, auth_headers, other_auth_headers):
    analyzed(client, auth_headers)
    assert dashboard(client, other_auth_headers) == EMPTY


def test_dashboard_requires_authentication(client):
    assert client.get(f"{API}/dashboard").status_code == 401