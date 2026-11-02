from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from app.engine.models import (
    IdentityNode,
    PolicyNode,
    PrincipalPolicy,
    PrincipalStatement,
    ResourceNode,
    Snapshot,
    Statement,
)
from app.models.enums import IdentityType, ResourceType


def _account_from_arn(arn: str) -> str | None:
    parts = arn.split(":")
    if len(parts) > 4 and parts[4]:
        return parts[4]
    return None


def _statement(raw: Mapping[str, Any]) -> Statement:
    return Statement(
        sid=raw.get("sid"),
        effect=raw["effect"],
        actions=tuple(raw["actions"]),
        resources=tuple(raw["resources"]),
        conditions=dict(raw.get("conditions") or {}),
    )


def _policy(raw: Mapping[str, Any]) -> PolicyNode:
    return PolicyNode(
        id=raw["external_id"],
        name=raw["name"],
        statements=tuple(_statement(item) for item in raw["statements"]),
    )


def _principal_policy(raw: Mapping[str, Any] | None) -> PrincipalPolicy | None:
    if raw is None:
        return None
    return PrincipalPolicy(
        statements=tuple(
            PrincipalStatement(
                sid=item.get("sid"),
                effect=item["effect"],
                principals=tuple(item["principals"]),
                actions=tuple(item["actions"]),
                conditions=dict(item.get("conditions") or {}),
            )
            for item in raw["statements"]
        )
    )


def _identity(raw: Mapping[str, Any]) -> IdentityNode:
    attributes = raw.get("attributes") or {}
    arn = raw["external_id"]
    return IdentityNode(
        arn=arn,
        name=raw["name"],
        identity_type=IdentityType(raw["identity_type"]),
        account_id=raw.get("account_id") or _account_from_arn(arn),
        policy_ids=tuple(attributes.get("policy_ids") or ()),
        trust_policy=_principal_policy(attributes.get("trust_policy")),
    )


def _resource(raw: Mapping[str, Any]) -> ResourceNode:
    attributes = raw.get("attributes") or {}
    arn = raw["external_id"]
    return ResourceNode(
        arn=arn,
        name=raw["name"],
        resource_type=ResourceType(raw["resource_type"]),
        is_sensitive=bool(raw.get("is_sensitive", False)),
        account_id=attributes.get("account_id") or _account_from_arn(arn),
        resource_policy=_principal_policy(attributes.get("resource_policy")),
    )


def _primary_account(identities: tuple[IdentityNode, ...]) -> str | None:
    counts = Counter(
        identity.account_id
        for identity in identities
        if identity.identity_type is not IdentityType.EXTERNAL_PRINCIPAL and identity.account_id
    )
    if not counts:
        return None
    highest = max(counts.values())
    return min(account for account, count in counts.items() if count == highest)


def build_snapshot(
    identities: Iterable[Mapping[str, Any]],
    resources: Iterable[Mapping[str, Any]],
    policies: Iterable[Mapping[str, Any]],
) -> Snapshot:
    policy_nodes = {item["external_id"]: _policy(item) for item in policies}
    identity_nodes = tuple(_identity(item) for item in identities)
    resource_nodes = tuple(_resource(item) for item in resources)
    for identity in identity_nodes:
        for policy_id in identity.policy_ids:
            if policy_id not in policy_nodes:
                raise ValueError(f"Identity {identity.arn} references unknown policy {policy_id}")
    return Snapshot(
        identities=identity_nodes,
        resources=resource_nodes,
        policies=policy_nodes,
        identity_index={node.arn: node for node in identity_nodes},
        resource_index={node.arn: node for node in resource_nodes},
        primary_account=_primary_account(identity_nodes),
    )