import uuid
from datetime import datetime

from pydantic import BaseModel

from app.models.enums import AnalysisStatus, Severity


class DashboardRun(BaseModel):
    run_id: uuid.UUID
    environment_id: uuid.UUID
    environment_name: str
    started_at: datetime
    status: AnalysisStatus
    finding_count: int
    attack_path_count: int


class DashboardFinding(BaseModel):
    finding_id: uuid.UUID
    run_id: uuid.UUID
    environment_id: uuid.UUID
    environment_name: str
    rule_id: str
    title: str
    severity: Severity
    risk_score: int


class DashboardRead(BaseModel):
    environment_count: int
    analyzed_environment_count: int
    identity_count: int
    sensitive_resource_count: int
    open_finding_count: int
    critical_high_finding_count: int
    attack_path_count: int
    recent_runs: list[DashboardRun]
    top_findings: list[DashboardFinding]