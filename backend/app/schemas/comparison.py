import uuid
from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel

from app.models.enums import PathClassification, Severity
from app.schemas.analysis import SeverityCounts


class ComparisonStatus(StrEnum):
    NEW = "new"
    PERSISTING = "persisting"
    NO_LONGER_DETECTED = "no_longer_detected"
    NOT_COMPARABLE = "not_comparable"


class StatusCounts(BaseModel):
    new: int = 0
    persisting: int = 0
    no_longer_detected: int = 0
    not_comparable: int = 0


class RunSide(BaseModel):
    run_id: uuid.UUID
    import_id: uuid.UUID
    import_source: str
    started_at: datetime
    analysis_version: str
    finding_count: int
    high_risk_finding_count: int
    attack_path_count: int
    paths_incomplete: bool
    severity_counts: SeverityCounts


class ComparedFinding(BaseModel):
    fingerprint: str
    status: ComparisonStatus
    rule_id: str
    title: str
    severity: Severity
    base_score: int | None
    target_score: int | None
    base_finding_id: uuid.UUID | None
    target_finding_id: uuid.UUID | None
    reason: str | None


class ComparedPath(BaseModel):
    fingerprint: str
    status: ComparisonStatus
    summary: str
    classification: PathClassification
    base_score: int | None
    target_score: int | None
    base_path_id: uuid.UUID | None
    target_path_id: uuid.UUID | None
    reason: str | None


class RunComparison(BaseModel):
    base: RunSide
    target: RunSide
    findings: list[ComparedFinding]
    finding_counts: StatusCounts
    attack_paths: list[ComparedPath]
    path_counts: StatusCounts
    caveats: list[str]