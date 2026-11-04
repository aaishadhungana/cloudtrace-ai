from dataclasses import dataclass
from functools import cached_property
from typing import Any

from app.models.enums import Decision, IdentityType, ResourceType

POLICY_KIND = "policy"
TRUST_KIND = "trust"
RESOURCE_POLICY_KIND = "resource_policy"

EFFECT_ALLOW = "allow"
EFFECT_DENY = "deny"
PUBLIC_PRINCIPAL = "*"

TARGET_IDENTITY = "identity"
TARGET_RESOURCE = "resource"


@dataclass(frozen=True)
class Statement:
    sid: str | None
    effect: str
    actions: tuple[str, ...]
    resources: tuple[str, ...]
    conditions: dict[str, Any]

    @property
    def has_conditions(self) -> bool:
        return bool(self.conditions)


@dataclass(frozen=True)
class PolicyNode:
    id: str
    name: str
    statements: tuple[Statement, ...]


@dataclass(frozen=True)
class PrincipalStatement:
    sid: str | None
    effect: str
    principals: tuple[str, ...]
    actions: tuple[str, ...]
    conditions: dict[str, Any]

    @property
    def has_conditions(self) -> bool:
        return bool(self.conditions)


@dataclass(frozen=True)
class PrincipalPolicy:
    statements: tuple[PrincipalStatement, ...]


@dataclass(frozen=True)
class IdentityNode:
    arn: str
    name: str
    identity_type: IdentityType
    account_id: str | None
    policy_ids: tuple[str, ...]
    trust_policy: PrincipalPolicy | None


@dataclass(frozen=True)
class ResourceNode:
    arn: str
    name: str
    resource_type: ResourceType
    is_sensitive: bool
    account_id: str | None
    resource_policy: PrincipalPolicy | None


@dataclass(frozen=True)
class StatementRef:
    kind: str
    owner: str
    index: int


@dataclass(frozen=True)
class Snapshot:
    identities: tuple[IdentityNode, ...]
    resources: tuple[ResourceNode, ...]
    policies: dict[str, PolicyNode]
    identity_index: dict[str, IdentityNode]
    resource_index: dict[str, ResourceNode]
    primary_account: str | None

    @cached_property
    def target_arns(self) -> tuple[str, ...]:
        return tuple(item.arn for item in self.identities) + tuple(
            item.arn for item in self.resources
        )

    def is_external(self, identity: IdentityNode) -> bool:
        if identity.identity_type is IdentityType.EXTERNAL_PRINCIPAL:
            return True
        return (
            self.primary_account is not None
            and identity.account_id is not None
            and identity.account_id != self.primary_account
        )

    def policy_statement(self, ref: StatementRef) -> Statement:
        return self.policies[ref.owner].statements[ref.index]

    def statement(self, ref: StatementRef) -> Statement | PrincipalStatement:
        if ref.kind == POLICY_KIND:
            return self.policy_statement(ref)
        if ref.kind == TRUST_KIND:
            trust = self.identity_index[ref.owner].trust_policy
            if trust is not None:
                return trust.statements[ref.index]
        if ref.kind == RESOURCE_POLICY_KIND:
            policy = self.resource_index[ref.owner].resource_policy
            if policy is not None:
                return policy.statements[ref.index]
        raise KeyError(ref)