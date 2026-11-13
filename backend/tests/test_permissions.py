from collections import Counter

from ai_support import analyzed, runs_url
from support import API


def permissions(client, headers, environment_id, run_id, query=""):
    response = client.get(
        f"{runs_url(environment_id)}/{run_id}/permissions{query}", headers=headers
    )
    assert response.status_code == 200
    return response.json()


def entry_named(page, source_name, source_kind):
    return next(
        item
        for item in page["items"]
        if item["source_name"] == source_name and item["source_kind"] == source_kind
    )


def rule_ids(entry):
    return {finding["rule_id"] for finding in entry["related_findings"]}


def test_every_statement_source_is_listed(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    page = permissions(client, auth_headers, environment["id"], run["id"])
    assert page["total"] == 18
    assert Counter(item["source_kind"] for item in page["items"]) == {
        "policy": 13,
        "trust": 4,
        "resource_policy": 1,
    }


def test_admin_statement_links_identity_and_finding(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    page = permissions(client, auth_headers, environment["id"], run["id"])
    admin = entry_named(page, "AdministratorAccess", "policy")
    assert admin["effect"] == "allow"
    assert admin["actions"] == ["*"]
    assert admin["targets"] == ["*"]
    assert admin["target_label"] == "resources"
    assert [item["name"] for item in admin["related_identities"]] == ["alice-admin"]
    assert "CT-IAM-001" in rule_ids(admin)


def test_deny_statement_is_explicit_and_linked(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    page = permissions(client, auth_headers, environment["id"], run["id"])
    denies = [item for item in page["items"] if item["effect"] == "deny"]
    assert len(denies) == 1
    assert denies[0]["source_name"] == "DenyCustomerData"
    assert [item["name"] for item in denies[0]["related_identities"]] == ["carol-analyst"]
    assert "CT-IAM-010" in rule_ids(denies[0])


def test_resource_and_trust_policies_carry_their_findings(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    page = permissions(client, auth_headers, environment["id"], run["id"])
    public = entry_named(page, "acme-public-assets", "resource_policy")
    assert public["targets"] == ["*"]
    assert public["target_label"] == "principals"
    assert "CT-IAM-008" in rule_ids(public)
    vendor = entry_named(page, "vendor-integration-role", "trust")
    assert vendor["actions"] == ["sts:AssumeRole"]
    assert "CT-IAM-005" in rule_ids(vendor)


def test_conditions_are_included(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    page = permissions(client, auth_headers, environment["id"], run["id"])
    trust = entry_named(page, "data-admin-role", "trust")
    assert trust["conditions"] == {"Bool": {"aws:MultiFactorAuthPresent": ["true"]}}


def test_pagination(client, auth_headers):
    environment, run = analyzed(client, auth_headers)
    first = permissions(client, auth_headers, environment["id"], run["id"], "?limit=5")
    assert first["total"] == 18 and len(first["items"]) == 5
    last = permissions(client, auth_headers, environment["id"], run["id"], "?offset=17")
    assert len(last["items"]) == 1
    beyond = permissions(client, auth_headers, environment["id"], run["id"], "?offset=18")
    assert beyond["items"] == []
    bad = client.get(
        f"{runs_url(environment['id'])}/{run['id']}/permissions?limit=0", headers=auth_headers
    )
    assert bad.status_code == 422


def test_permissions_access_control(client, auth_headers, other_auth_headers):
    environment, run = analyzed(client, auth_headers)
    url = f"{runs_url(environment['id'])}/{run['id']}/permissions"
    assert client.get(url).status_code == 401
    assert client.get(url, headers=other_auth_headers).status_code == 404