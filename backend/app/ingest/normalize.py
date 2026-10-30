import hashlib
from dataclasses import dataclass
from typing import Any

from app.ingest.schema import (
    SUPPORTED_SCHEMA_VERSION,
    ImportDocument,
    PolicyStatement,
    PrincipalPolicy,
    PrincipalStatement,
)


@dataclass(frozen=True)
class NormalizedImport:
    schema_version: str
    identities: list[dict[str, Any]]
    resources: list[dict[str, Any]]
    policies: list[dict[str, Any]]
    metadata: dict[str, Any]


def _unique(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _conditions(
    conditions: dict[str, dict[str, str | list[str]]],
) -> dict[str, dict[str, list[str]]]:
    return {
        operator: {
            key: [values] if isinstance(values, str) else _unique(values)
            for key, values in clauses.items()
        }
        for operator, clauses in conditions.items()
    }


def _policy_statement(statement: PolicyStatement) -> dict[str, Any]:
    return {
        "sid": statement.sid,
        "effect": statement.effect.lower(),
        "actions": _unique(statement.actions),
        "resources": _unique(statement.resources),
        "conditions": _conditions(statement.conditions),
    }


def _principal_statement(statement: PrincipalStatement) -> dict[str, Any]:
    return {
        "sid": statement.sid,
        "effect": statement.effect.lower(),
        "principals": _unique(statement.principals),
        "actions": _unique(statement.actions),
        "conditions": _conditions(statement.conditions),
    }


def _principal_policy(policy: PrincipalPolicy | None) -> dict[str, Any] | None:
    if policy is None:
        return None
    return {"statements": [_principal_statement(item) for item in policy.statements]}


def _count_statements(
    identities: list[dict[str, Any]],
    resources: list[dict[str, Any]],
    policies: list[dict[str, Any]],
) -> int:
    total = sum(len(policy["statements"]) for policy in policies)
    for identity in identities:
        trust_policy = identity["attributes"]["trust_policy"]
        if trust_policy is not None:
            total += len(trust_policy["statements"])
    for resource in resources:
        resource_policy = resource["attributes"]["resource_policy"]
        if resource_policy is not None:
            total += len(resource_policy["statements"])
    return total


def normalize_document(document: ImportDocument, body: bytes) -> NormalizedImport:
    identities = [
        {
            "external_id": item.arn,
            "name": item.name,
            "identity_type": item.type,
            "account_id": item.account_id,
            "attributes": {
                "policy_ids": _unique(item.policy_ids),
                "trust_policy": _principal_policy(item.trust_policy),
            },
        }
        for item in document.identities
    ]
    resources = [
        {
            "external_id": item.arn,
            "name": item.name,
            "resource_type": item.type,
            "is_sensitive": item.sensitive,
            "attributes": {
                "account_id": item.account_id,
                "resource_policy": _principal_policy(item.resource_policy),
            },
        }
        for item in document.resources
    ]
    policies = [
        {
            "external_id": item.id,
            "name": item.name,
            "statements": [_policy_statement(statement) for statement in item.statements],
        }
        for item in document.policies
    ]
    metadata = {
        "identity_count": len(identities),
        "resource_count": len(resources),
        "policy_count": len(policies),
        "statement_count": _count_statements(identities, resources, policies),
        "sensitive_resource_count": sum(1 for item in resources if item["is_sensitive"]),
        "content_sha256": hashlib.sha256(body).hexdigest(),
    }
    return NormalizedImport(
        schema_version=SUPPORTED_SCHEMA_VERSION,
        identities=identities,
        resources=resources,
        policies=policies,
        metadata=metadata,
    )