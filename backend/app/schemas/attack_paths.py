import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from app.models.enums import Decision, PathClassification, RelationshipType, Severity
from app.schemas.analysis import RiskFactorRead


class AttackPathSummary(BaseModel):
    id: uuid.UUID
    analysis_run_id: uuid.UUID
    start_identity_id: uuid.UUID
    start_identity_name: str
    target_resource_id: uuid.UUID
    target_resource_name: str
    classification: PathClassification
    risk_score: int
    severity: Severity
    step_count: int
    summary: str
    created_at: datetime


class PathNodeRead(BaseModel):
    id: uuid.UUID | None
    arn: str
    name: str
    kind: str
    type: str
    is_external: bool
    is_sensitive: bool
    position: str


class PathEdgeRead(BaseModel):
    source: str
    target: str
    relationship: RelationshipType
    relationships: list[RelationshipType]
    decision: Decision
    actions: list[str]
    notes: list[str]
    assumption: str | None


class AttackPathDetail(AttackPathSummary):
    raw_score: int
    risk_factors: list[RiskFactorRead]
    nodes: list[PathNodeRead]
    edges: list[PathEdgeRead]
    evidence: list[dict[str, Any]]


class AttackPathList(BaseModel):
    total: int
    items: list[AttackPathSummary]