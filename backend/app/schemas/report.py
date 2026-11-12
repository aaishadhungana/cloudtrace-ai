import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.enums import CloudProvider, PathClassification, Severity
from app.schemas.ai import AIAnalysisRead
from app.schemas.analysis import SeverityCounts


class ReportEnvironment(BaseModel):
    name: str
    cloud_provider: CloudProvider
    description: str | None


class ReportScope(BaseModel):
    run_id: uuid.UUID
    started_at: datetime
    completed_at: datetime | None
    analysis_version: str
    import_source: str
    import_created_at: datetime
    identity_count: int
    resource_count: int
    sensitive_resource_count: int
    policy_count: int
    statement_count: int


class ReportFinding(BaseModel):
    id: uuid.UUID
    rule_id: str
    title: str
    severity: Severity
    risk_score: int
    identity_name: str | None
    resource_name: str | None
    explanation: str
    remediation: str


class ReportPath(BaseModel):
    id: uuid.UUID
    summary: str
    classification: PathClassification
    severity: Severity
    risk_score: int
    start: str
    target: str
    step_count: int


class ReportRead(BaseModel):
    generated_at: datetime
    environment: ReportEnvironment
    scope: ReportScope
    finding_total: int
    severity_counts: SeverityCounts
    findings: list[ReportFinding]
    findings_not_shown: int
    attack_path_total: int
    attack_paths: list[ReportPath]
    attack_paths_not_shown: int
    paths_incomplete: bool
    ai_summary: AIAnalysisRead | None
    limitations: list[str]