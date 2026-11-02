from app.engine.rules.registry import RULES
from app.models.enums import Severity
from engine_support import (
    allow,
    analyze_document,
    bucket,
    bucket_arn,
    deny,
    document,
    external_arn,
    external_principal,
    findings_with,
    policy,
    principal_statement,
    role,
    role_arn,
    rule_ids,
    user,
    user_arn,
)

MFA = {"Bool": {"aws:MultiFactorAuthPresent": ["true"]}}
ACME_PATTERN = [bucket_arn("acme-*"), f"{bucket_arn('acme-*')}/*"]
CUSTOMER_DATA = [bucket_arn("acme-customer-data"), f"{bucket_arn('acme-customer-data')}/*"]


def acme_buckets():
    return [bucket("acme-reports"), bucket("acme-customer-data", sensitive=True)]


def test_registry_has_unique_stable_rule_ids():
    ids = [rule.info.rule_id for rule in RULES]
    assert ids == [f"CT-IAM-{number:03d}" for number in range(1, 11)]
    assert all(rule.info.description and rule.info.title for rule in RULES)


def test_admin_wildcard_fires_for_full_wildcard():
    doc = document([user("u", ["p"])], acme_buckets(), [policy("p", allow(["*"], ["*"]))])
    result = analyze_document(doc)
    assert rule_ids(result) == {"CT-IAM-001"}
    finding = findings_with(result, "CT-IAM-001")[0]
    assert finding.identity_arn == user_arn("u")
    assert finding.assessment.score == 80
    assert finding.assessment.severity is Severity.CRITICAL
    assert finding.evidence[0]["kind"] == "policy_statement"
    assert finding.evidence[0]["actions"] == ["*"]


def test_conditional_admin_is_scored_lower():
    doc = document(
        [user("u", ["p"])], acme_buckets(), [policy("p", allow(["*"], ["*"], MFA))]
    )
    finding = findings_with(analyze_document(doc), "CT-IAM-001")[0]
    assert finding.assessment.score == 70
    assert finding.assessment.severity is Severity.HIGH


def test_findings_depend_on_permissions_not_names():
    doc = document(
        [user("admin-superuser", ["p"])],
        [bucket("reports")],
        [policy("p", allow(["s3:GetObject"], [f"{bucket_arn('reports')}/*"]))],
    )
    assert analyze_document(doc).findings == ()


def test_restricted_identity_has_no_findings():
    doc = document(
        [user("u", ["p"])],
        [bucket("reports"), bucket("customers", sensitive=True)],
        [policy("p", allow(["s3:GetObject", "s3:ListBucket"], [bucket_arn("reports"), f"{bucket_arn('reports')}/*"]))],
    )
    assert analyze_document(doc).findings == ()


def test_service_wildcard_fires_without_admin_finding():
    doc = document([user("u", ["p"])], acme_buckets(), [policy("p", allow(["s3:*"], ["*"]))])
    result = analyze_document(doc)
    assert rule_ids(result) == {"CT-IAM-002"}
    assert findings_with(result, "CT-IAM-002")[0].assessment.score == 65


def test_service_wildcard_scoped_to_one_bucket_is_not_reported():
    doc = document(
        [user("u", ["p"])],
        acme_buckets(),
        [policy("p", allow(["s3:*"], CUSTOMER_DATA))],
    )
    assert analyze_document(doc).findings == ()


def test_broad_pattern_reaching_sensitive_resource_is_reported():
    doc = document(
        [user("u", ["p"])],
        acme_buckets(),
        [policy("p", allow(["s3:GetObject", "s3:ListBucket"], ACME_PATTERN))],
    )
    result = analyze_document(doc)
    assert rule_ids(result) == {"CT-IAM-003"}
    finding = findings_with(result, "CT-IAM-003")[0]
    assert finding.resource_arn == bucket_arn("acme-customer-data")
    assert finding.assessment.score == 50


def test_exact_grant_to_sensitive_resource_is_not_reported():
    doc = document(
        [user("u", ["p"])],
        acme_buckets(),
        [policy("p", allow(["s3:GetObject", "s3:ListBucket"], CUSTOMER_DATA))],
    )
    assert analyze_document(doc).findings == ()


def test_explicit_deny_turns_broad_grant_into_deny_dependency():
    doc = document(
        [user("u", ["p"])],
        acme_buckets(),
        [
            policy(
                "p",
                allow(["s3:GetObject", "s3:ListBucket"], ACME_PATTERN),
                deny(["s3:*"], CUSTOMER_DATA),
            )
        ],
    )
    result = analyze_document(doc)
    assert rule_ids(result) == {"CT-IAM-010"}
    assert findings_with(result, "CT-IAM-010")[0].assessment.score == 33


def test_trust_any_principal():
    doc = document(
        [user("u"), role("open", trusted=["*"], policies=["p"])],
        [bucket("reports")],
        [policy("p", allow(["s3:GetObject"], [f"{bucket_arn('reports')}/*"]))],
    )
    result = analyze_document(doc)
    assert rule_ids(result) == {"CT-IAM-004"}
    finding = findings_with(result, "CT-IAM-004")[0]
    assert finding.assessment.score == 70
    assert finding.identity_arn == role_arn("open")


def test_cross_account_trust_is_reported_for_external_principals_only():
    external = document(
        [external_principal(), role("partner", trusted=[external_arn()])]
    )
    internal = document([user("u"), role("internal", trusted=[user_arn("u")])])
    assert rule_ids(analyze_document(external)) == {"CT-IAM-005"}
    assert analyze_document(internal).findings == ()
    assert findings_with(analyze_document(external), "CT-IAM-005")[0].assessment.score == 45


def test_policy_modification_scores_critical_when_a_sensitive_resource_exists():
    doc = document(
        [user("u", ["p"])],
        acme_buckets(),
        [policy("p", allow(["iam:PutUserPolicy"], ["*"]))],
    )
    result = analyze_document(doc)
    assert rule_ids(result) == {"CT-IAM-006"}
    assert findings_with(result, "CT-IAM-006")[0].assessment.severity is Severity.CRITICAL


def test_policy_modification_without_sensitive_resources_is_lower():
    doc = document(
        [user("u", ["p"])],
        [bucket("reports")],
        [policy("p", allow(["iam:PutUserPolicy"], ["*"]))],
    )
    assert findings_with(analyze_document(doc), "CT-IAM-006")[0].assessment.score == 55


def test_admin_identity_does_not_also_get_escalation_findings():
    doc = document(
        [user("u", ["p"]), role("r1"), role("r2")],
        acme_buckets(),
        [policy("p", allow(["*"], ["*"]))],
    )
    assert rule_ids(analyze_document(doc)) == {"CT-IAM-001"}


def test_pass_role_on_any_role_is_reported():
    doc = document(
        [user("u", ["p"]), role("r1"), role("r2")],
        policies=[policy("p", allow(["iam:PassRole"], ["*"]))],
    )
    result = analyze_document(doc)
    assert rule_ids(result) == {"CT-IAM-007"}
    assert findings_with(result, "CT-IAM-007")[0].assessment.score == 29


def test_pass_role_on_one_specific_role_is_not_reported():
    doc = document(
        [user("u", ["p"]), role("r1"), role("r2")],
        policies=[policy("p", allow(["iam:PassRole"], [role_arn("r1")]))],
    )
    assert analyze_document(doc).findings == ()


def test_public_read_of_sensitive_resource_is_critical():
    doc = document(
        [user("nobody")],
        [bucket("customers", sensitive=True, policy_statements=[principal_statement(["*"], ["s3:GetObject"])])],
    )
    result = analyze_document(doc)
    assert rule_ids(result) == {"CT-IAM-008"}
    finding = findings_with(result, "CT-IAM-008")[0]
    assert finding.assessment.score == 80
    assert finding.resource_arn == bucket_arn("customers")


def test_public_write_is_scored_higher_than_public_read():
    doc = document(
        [user("nobody")],
        [bucket("site", policy_statements=[principal_statement(["*"], ["s3:PutObject"])])],
    )
    assert findings_with(analyze_document(doc), "CT-IAM-008")[0].assessment.score == 65


def test_named_external_principal_in_resource_policy_is_not_public():
    doc = document(
        [user("alice"), external_principal()],
        [bucket("data", policy_statements=[principal_statement([external_arn()], ["s3:GetObject"])])],
    )
    result = analyze_document(doc)
    assert rule_ids(result) == {"CT-IAM-009"}
    assert findings_with(result, "CT-IAM-009")[0].assessment.score == 25


def test_every_finding_carries_evidence_explanation_and_remediation():
    doc = document(
        [user("u", ["p"]), role("open", trusted=["*"])],
        acme_buckets(),
        [policy("p", allow(["*"], ["*"]))],
    )
    result = analyze_document(doc)
    assert result.findings
    for finding in result.findings:
        assert finding.evidence
        assert finding.explanation
        assert finding.remediation
        assert finding.assessment.factors