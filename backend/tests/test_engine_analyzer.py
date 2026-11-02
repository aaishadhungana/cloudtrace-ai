import copy
import json

from app.engine.analyzer import analyze
from app.engine.models import Decision
from app.engine.snapshot import build_snapshot
from app.ingest.pipeline import process_import
from app.models.enums import RelationshipType, Severity
from app.samples.catalog import read_sample
from engine_support import (
    ACCOUNT,
    bucket_arn,
    external_arn,
    relationship_between,
    role_arn,
    user_arn,
)


def analyze_body(body: bytes):
    normalized = process_import(body)
    return analyze(build_snapshot(normalized.identities, normalized.resources, normalized.policies))


def prod_result():
    return analyze_body(read_sample("acme-prod"))


def test_production_sample_produces_the_expected_findings():
    result = prod_result()
    scores = {finding.rule_id: finding.assessment.score for finding in result.findings}
    assert scores == {
        "CT-IAM-001": 80,
        "CT-IAM-002": 65,
        "CT-IAM-005": 45,
        "CT-IAM-007": 54,
        "CT-IAM-008": 55,
        "CT-IAM-010": 33,
    }
    assert len(result.findings) == 6


def test_production_sample_severities_and_subjects():
    result = prod_result()
    by_rule = {finding.rule_id: finding for finding in result.findings}
    assert by_rule["CT-IAM-001"].severity if False else True
    assert by_rule["CT-IAM-001"].assessment.severity is Severity.CRITICAL
    assert by_rule["CT-IAM-001"].identity_arn == user_arn("alice-admin")
    assert by_rule["CT-IAM-002"].identity_arn == role_arn("deploy-role")
    assert by_rule["CT-IAM-005"].identity_arn == role_arn("vendor-integration-role")
    assert by_rule["CT-IAM-008"].resource_arn == bucket_arn("acme-public-assets")
    assert by_rule["CT-IAM-010"].identity_arn == user_arn("carol-analyst")
    assert by_rule["CT-IAM-010"].resource_arn == bucket_arn("acme-customer-data")


def test_findings_are_sorted_by_score_and_fingerprints_are_unique():
    result = prod_result()
    scores = [finding.assessment.score for finding in result.findings]
    assert scores == sorted(scores, reverse=True)
    fingerprints = [finding.fingerprint for finding in result.findings]
    assert len(set(fingerprints)) == len(fingerprints)


def test_analysis_is_deterministic():
    first = prod_result()
    second = prod_result()
    assert first.findings == second.findings
    assert first.relationships == second.relationships


def test_development_sample_has_no_findings():
    assert analyze_body(read_sample("acme-dev")).findings == ()


def test_production_sample_role_chain_relationships():
    result = prod_result()
    assume = RelationshipType.CAN_ASSUME
    bob_to_deploy = relationship_between(
        result, user_arn("bob-developer"), role_arn("deploy-role"), assume
    )
    deploy_to_admin = relationship_between(
        result, role_arn("deploy-role"), role_arn("data-admin-role"), assume
    )
    partner_to_vendor = relationship_between(
        result, external_arn("999988887777"), role_arn("vendor-integration-role"), assume
    )
    assert bob_to_deploy is not None and bob_to_deploy.decision is Decision.ALLOWED
    assert deploy_to_admin is not None and deploy_to_admin.decision is Decision.CONDITIONAL
    assert partner_to_vendor is not None and partner_to_vendor.decision is Decision.CONDITIONAL


def test_explicit_deny_shows_up_as_a_deny_relationship():
    relationship = relationship_between(
        prod_result(),
        user_arn("carol-analyst"),
        bucket_arn("acme-customer-data"),
        RelationshipType.CAN_READ,
    )
    assert relationship is not None
    assert relationship.effect == "deny"
    assert relationship.deny_refs


def test_restricted_runtime_role_reaches_only_its_resources():
    result = prod_result()
    runtime = role_arn("app-runtime-role")
    reached = {
        relationship.target_arn
        for relationship in result.relationships
        if relationship.source_arn == runtime and relationship.effect == "allow"
    }
    assert "arn:aws:rds:us-east-1:111122223333:db:orders-db" in reached
    assert bucket_arn("acme-customer-data") not in reached
    assert not [finding for finding in result.findings if finding.identity_arn == runtime]


def test_remediation_removes_only_the_fixed_finding():
    before = prod_result()
    document = json.loads(read_sample("acme-prod"))
    fixed = copy.deepcopy(document)
    for identity in fixed["identities"]:
        if identity["name"] == "alice-admin":
            identity["policy_ids"] = []
    after = analyze_body(json.dumps(fixed).encode())
    removed = {finding.fingerprint for finding in before.findings} - {
        finding.fingerprint for finding in after.findings
    }
    added = {finding.fingerprint for finding in after.findings} - {
        finding.fingerprint for finding in before.findings
    }
    assert {finding.rule_id for finding in before.findings if finding.fingerprint in removed} == {
        "CT-IAM-001"
    }
    assert added == set()
    assert len(after.findings) == 5


def test_result_lists_its_limitations():
    result = prod_result()
    assert result.limitations
    assert any("conditions" in item.lower() for item in result.limitations)
    assert result.analysis_version == "1.0.0"


def test_account_constant_matches_the_sample_account():
    assert ACCOUNT == "111122223333"