from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from app.models.enums import Severity


class Capability(StrEnum):
    ADMIN_WILDCARD = "admin_wildcard"
    POLICY_MODIFICATION = "policy_modification"
    SERVICE_WILDCARD = "service_wildcard"
    SENSITIVE_BROAD_GRANT = "sensitive_broad_grant"
    TRUST_ANY_PRINCIPAL = "trust_any_principal"
    CROSS_ACCOUNT_TRUST = "cross_account_trust"
    PASS_ROLE_WILDCARD = "pass_role_wildcard"
    PUBLIC_READ = "public_read"
    PUBLIC_WRITE = "public_write"
    CROSS_ACCOUNT_RESOURCE_GRANT = "cross_account_resource_grant"
    DENY_DEPENDENCY = "deny_dependency"


class Exposure(StrEnum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    PUBLIC = "public"


CAPABILITY_POINTS: dict[Capability, int] = {
    Capability.ADMIN_WILDCARD: 45,
    Capability.POLICY_MODIFICATION: 45,
    Capability.SERVICE_WILDCARD: 30,
    Capability.SENSITIVE_BROAD_GRANT: 25,
    Capability.TRUST_ANY_PRINCIPAL: 40,
    Capability.CROSS_ACCOUNT_TRUST: 30,
    Capability.PASS_ROLE_WILDCARD: 24,
    Capability.PUBLIC_READ: 30,
    Capability.PUBLIC_WRITE: 40,
    Capability.CROSS_ACCOUNT_RESOURCE_GRANT: 15,
    Capability.DENY_DEPENDENCY: 8,
}

CAPABILITY_LABELS: dict[Capability, str] = {
    Capability.ADMIN_WILDCARD: "All actions allowed on all resources",
    Capability.POLICY_MODIFICATION: "Can change IAM policies",
    Capability.SERVICE_WILDCARD: "All actions of a service allowed on broad resources",
    Capability.SENSITIVE_BROAD_GRANT: "Sensitive resource granted through a broad resource pattern",
    Capability.TRUST_ANY_PRINCIPAL: "Role trust policy allows any principal",
    Capability.CROSS_ACCOUNT_TRUST: "Role trust policy allows an external principal",
    Capability.PASS_ROLE_WILDCARD: "Can pass any role",
    Capability.PUBLIC_READ: "Resource policy allows public read access",
    Capability.PUBLIC_WRITE: "Resource policy allows public write access",
    Capability.CROSS_ACCOUNT_RESOURCE_GRANT: "Resource policy grants an external principal access",
    Capability.DENY_DEPENDENCY: "Access is blocked only by an explicit Deny",
}

EXPOSURE_POINTS: dict[Exposure, int] = {
    Exposure.INTERNAL: 0,
    Exposure.EXTERNAL: 10,
    Exposure.PUBLIC: 25,
}

EXPOSURE_LABELS: dict[Exposure, str] = {
    Exposure.INTERNAL: "Internal to the modeled account",
    Exposure.EXTERNAL: "Involves a principal outside the modeled account",
    Exposure.PUBLIC: "Open to any principal",
}

SENSITIVE_TARGET_POINTS = 25
WRITE_POINTS = 10
ROLE_CHAIN_POINTS = 5
CONDITION_DISCOUNT = -10

SEVERITY_THRESHOLDS: tuple[tuple[int, Severity], ...] = (
    (80, Severity.CRITICAL),
    (60, Severity.HIGH),
    (40, Severity.MEDIUM),
    (20, Severity.LOW),
)


@dataclass(frozen=True)
class RiskFactor:
    name: str
    points: int
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {"name": self.name, "points": self.points, "detail": self.detail}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    raw_score: int
    severity: Severity
    factors: tuple[RiskFactor, ...]

    def factor_dicts(self) -> list[dict[str, Any]]:
        return [factor.as_dict() for factor in self.factors]


def severity_for(score: int) -> Severity:
    for threshold, severity in SEVERITY_THRESHOLDS:
        if score >= threshold:
            return severity
    return Severity.INFO


def assess(
    capability: Capability,
    *,
    exposure: Exposure = Exposure.INTERNAL,
    reaches_sensitive: bool = False,
    can_write: bool = False,
    role_chain: bool = False,
    conditional: bool = False,
) -> RiskAssessment:
    factors = [
        RiskFactor("capability", CAPABILITY_POINTS[capability], CAPABILITY_LABELS[capability])
    ]
    if exposure is not Exposure.INTERNAL:
        factors.append(RiskFactor("exposure", EXPOSURE_POINTS[exposure], EXPOSURE_LABELS[exposure]))
    if reaches_sensitive:
        factors.append(
            RiskFactor(
                "sensitive_target", SENSITIVE_TARGET_POINTS, "Reaches a resource marked sensitive"
            )
        )
    if can_write:
        factors.append(
            RiskFactor("write_capability", WRITE_POINTS, "Can write or change resources or policies")
        )
    if role_chain:
        factors.append(
            RiskFactor("role_chain", ROLE_CHAIN_POINTS, "Involves role assumption or role passing")
        )
    if conditional:
        factors.append(
            RiskFactor(
                "condition_restriction",
                CONDITION_DISCOUNT,
                "Grant is restricted by conditions that cannot be evaluated here",
            )
        )
    raw_score = sum(factor.points for factor in factors)
    score = max(0, min(100, raw_score))
    return RiskAssessment(
        score=score, raw_score=raw_score, severity=severity_for(score), factors=tuple(factors)
    )