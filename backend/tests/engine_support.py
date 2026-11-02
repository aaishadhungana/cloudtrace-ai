import json
from typing import Any

from app.engine.analyzer import AnalysisResult, analyze
from app.engine.evaluation import EffectiveRelationship
from app.engine.models import Snapshot
from app.engine.snapshot import build_snapshot
from app.ingest.pipeline import process_import
from app.models.enums import RelationshipType

ACCOUNT = "111122223333"
EXTERNAL_ACCOUNT = "999988887777"


def user_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:user/{name}"


def role_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def bucket_arn(name: str) -> str:
    return f"arn:aws:s3:::{name}"


def external_arn(account: str = EXTERNAL_ACCOUNT) -> str:
    return f"arn:aws:iam::{account}:root"


def user(name: str, policies: list[str] | tuple[str, ...] = ()) -> dict[str, Any]:
    return {"arn": user_arn(name), "name": name, "type": "iam_user", "policy_ids": list(policies)}


def role(
    name: str,
    trusted: list[str] | tuple[str, ...] = (),
    policies: list[str] | tuple[str, ...] = (),
    trust_conditions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "arn": role_arn(name),
        "name": name,
        "type": "iam_role",
        "policy_ids": list(policies),
    }
    if trusted:
        statement: dict[str, Any] = {
            "effect": "Allow",
            "principals": list(trusted),
            "actions": ["sts:AssumeRole"],
        }
        if trust_conditions:
            statement["conditions"] = trust_conditions
        identity["trust_policy"] = {"statements": [statement]}
    return identity


def external_principal(account: str = EXTERNAL_ACCOUNT) -> dict[str, Any]:
    return {
        "arn": external_arn(account),
        "name": f"external-{account}",
        "type": "external_principal",
    }


def principal_statement(
    principals: list[str],
    actions: list[str],
    conditions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    statement: dict[str, Any] = {"effect": "Allow", "principals": principals, "actions": actions}
    if conditions:
        statement["conditions"] = conditions
    return statement


def bucket(
    name: str,
    sensitive: bool = False,
    policy_statements: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    resource: dict[str, Any] = {
        "arn": bucket_arn(name),
        "name": name,
        "type": "storage_bucket",
        "sensitive": sensitive,
    }
    if policy_statements:
        resource["resource_policy"] = {"statements": policy_statements}
    return resource


def allow(
    actions: list[str], resources: list[str], conditions: dict[str, Any] | None = None
) -> dict[str, Any]:
    statement: dict[str, Any] = {"effect": "Allow", "actions": actions, "resources": resources}
    if conditions:
        statement["conditions"] = conditions
    return statement


def deny(
    actions: list[str], resources: list[str], conditions: dict[str, Any] | None = None
) -> dict[str, Any]:
    statement = allow(actions, resources, conditions)
    statement["effect"] = "Deny"
    return statement


def policy(policy_id: str, *statements: dict[str, Any]) -> dict[str, Any]:
    return {"id": policy_id, "name": policy_id, "statements": list(statements)}


def document(
    identities: list[dict[str, Any]],
    resources: list[dict[str, Any]] | None = None,
    policies: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "identities": identities,
        "resources": resources or [],
        "policies": policies or [],
    }


def snapshot_of(doc: dict[str, Any]) -> Snapshot:
    normalized = process_import(json.dumps(doc).encode())
    return build_snapshot(normalized.identities, normalized.resources, normalized.policies)


def analyze_document(doc: dict[str, Any]) -> AnalysisResult:
    return analyze(snapshot_of(doc))


def rule_ids(result: AnalysisResult) -> set[str]:
    return {finding.rule_id for finding in result.findings}


def findings_with(result: AnalysisResult, rule_id: str):
    return [finding for finding in result.findings if finding.rule_id == rule_id]


def relationship_between(
    result: AnalysisResult, source: str, target: str, relationship_type: RelationshipType
) -> EffectiveRelationship | None:
    for relationship in result.relationships:
        key = (relationship.source_arn, relationship.target_arn, relationship.relationship_type)
        if key == (source, target, relationship_type):
            return relationship
    return None