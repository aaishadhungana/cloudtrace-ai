import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict

from app.models.enums import (
    AnalysisStatus,
    Decision,
    Effect,
    FindingStatus,
    IdentityType,
    RelationshipType,
    Severity,
)


class AnalysisRunCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    import_id: uuid.UUID | None = None


class SeverityCounts(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class AnalysisRunRead(BaseModel):
    id: uuid.UUID
    environment_id: uuid.UUID
    import_id: uuid.UUID
    status: AnalysisStatus
    analysis_version: str
    started_at: datetime
    completed_at: datetime | None
    finding_count: int
    severity_counts: SeverityCounts


class AnalysisRunDetail(AnalysisRunRead):
    limitations: list[str]
    import_source: str
    import_created_at: datetime


class RuleRead(BaseModel):
    rule_id: str
    title: str
    description: str
    finding_type: str


class RiskFactorRead(BaseModel):
    name: str
    points: int
    detail: str


class FindingSummary(BaseModel):
    id: uuid.UUID
    analysis_run_id: uuid.UUID
    rule_id: str
    finding_type: str
    title: str
    severity: Severity
    risk_score: int
    status: FindingStatus
    identity_id: uuid.UUID | None
    identity_name: str | None
    resource_id: uuid.UUID | None
    resource_name: str | None
    created_at: datetime


class FindingDetail(FindingSummary):
    identity_arn: str | None
    resource_arn: str | None
    explanation: str
    remediation: str
    raw_score: int
    risk_factors: list[RiskFactorRead]
    evidence: list[dict[str, Any]]


class FindingList(BaseModel):
    total: int
    items: list[FindingSummary]


class IdentitySummary(BaseModel):
    id: uuid.UUID
    arn: str
    name: str
    identity_type: IdentityType
    account_id: str | None
    policy_names: list[str]
    finding_count: int
    max_risk_score: int | None
    risk_level: Severity | None
    reachable_target_count: int
    sensitive_target_count: int


class PolicyRead(BaseModel):
    id: str
    name: str
    statements: list[dict[str, Any]]


class AccessEntry(BaseModel):
    target_kind: str
    target_id: uuid.UUID
    target_arn: str
    target_name: str
    is_sensitive: bool
    relationship_type: RelationshipType
    effect: Effect
    decision: Decision
    actions: list[str]
    notes: list[str]
    statements: list[dict[str, Any]]


class IdentityDetail(IdentitySummary):
    policies: list[PolicyRead]
    trust_policy: dict[str, Any] | None
    access: list[AccessEntry]
    findings: list[FindingSummary]