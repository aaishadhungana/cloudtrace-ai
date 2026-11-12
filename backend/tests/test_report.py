from engine_support import allow, document, policy, user_arn
from ai_support import FakeAnalyst, ai_url, analyzed, runs_url, use_analyst
from support import API, create_environment, encode_document, post_import


def report_url(environment_id, run_id, suffix=""):
    return f"{runs_url(environment_id)}/{run_id}/report{suffix}"


def test_report_describes_scope_findings_and_paths(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    response = client.get(report_url(environment["id"], run["id"]), headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["environment"]["name"] == "prod"
    assert body["environment"]["cloud_provider"] == "aws"
    assert body["scope"]["identity_count"] == 9
    assert body["scope"]["resource_count"] == 6
    assert body["scope"]["policy_count"] == 8
    assert body["scope"]["sensitive_resource_count"] == 3
    assert body["scope"]["statement_count"] > 0
    assert body["scope"]["import_source"] == "acme-prod.json"
    assert body["finding_total"] == 6
    assert body["severity_counts"]["critical"] == 1
    assert [item["risk_score"] for item in body["findings"]] == [80, 65, 55, 54, 45, 33]
    assert body["findings_not_shown"] == 0
    assert body["attack_path_total"] == 9
    assert len(body["attack_paths"]) == 9
    assert body["ai_summary"] is None
    assert body["limitations"]
    assert body["generated_at"]


def test_report_includes_a_stored_ai_summary_only_when_one_exists(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    assert client.get(report_url(environment["id"], run["id"]), headers=auth_headers).json()["ai_summary"] is None
    use_analyst(FakeAnalyst())
    client.post(ai_url(environment["id"], run["id"], "summary"), headers=auth_headers)
    body = client.get(report_url(environment["id"], run["id"]), headers=auth_headers).json()
    assert body["ai_summary"]["notice"].startswith("AI-generated")
    assert body["ai_summary"]["content"]["overview"]


def test_markdown_download(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    response = client.get(report_url(environment["id"], run["id"], "/markdown"), headers=auth_headers)
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/markdown")
    assert "attachment" in response.headers["content-disposition"]
    text = response.text
    assert "# CloudTrace AI security report" in text
    assert "alice-admin has wildcard administrative permissions" in text
    assert "CT-IAM-001" in text
    assert "## Limitations" in text
    assert "AI-generated summary" not in text

    use_analyst(FakeAnalyst())
    client.post(ai_url(environment["id"], run["id"], "summary"), headers=auth_headers)
    with_ai = client.get(report_url(environment["id"], run["id"], "/markdown"), headers=auth_headers)
    assert "AI-generated summary (not verified evidence)" in with_ai.text


def test_markdown_escapes_imported_text(client, auth_headers):
    hostile = "x`y\n<script>alert(1)</script>"
    doc = document(
        [{"arn": user_arn("mallory"), "name": hostile, "type": "iam_user", "policy_ids": ["p"]}],
        policies=[policy("p", allow(["*"], ["*"]))],
    )
    environment = create_environment(client, auth_headers, "hostile")
    assert post_import(client, auth_headers, environment["id"], encode_document(doc)).status_code == 201
    run = client.post(runs_url(environment["id"]), headers=auth_headers).json()
    text = client.get(report_url(environment["id"], run["id"], "/markdown"), headers=auth_headers).text
    assert "<script>" not in text
    assert "&lt;script&gt;" in text
    assert "`y" not in text


def test_report_requires_a_completed_run(client, auth_headers, monkeypatch):
    environment, run = analyzed(client, auth_headers)

    def explode(snapshot):
        raise RuntimeError("internal detail")

    monkeypatch.setattr("app.services.analysis.analyze", explode)
    client.post(runs_url(environment["id"]), headers=auth_headers)
    runs = client.get(runs_url(environment["id"]), headers=auth_headers).json()
    failed = next(item for item in runs if item["status"] == "failed")
    assert client.get(report_url(environment["id"], failed["id"]), headers=auth_headers).status_code == 409


def test_report_access_control(client, auth_headers, other_auth_headers):
    environment, run = analyzed(client, auth_headers)
    url = report_url(environment["id"], run["id"])
    assert client.get(url).status_code == 401
    assert client.get(url, headers=other_auth_headers).status_code == 404
    assert client.get(f"{url}/markdown", headers=other_auth_headers).status_code == 404