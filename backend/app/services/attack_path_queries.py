import uuid
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.engine.scoring import severity_for
from app.models import AnalysisRun, AttackPath, Identity, Resource
from app.models.enums import PathClassification
from app.schemas.analysis import RiskFactorRead
from app.schemas.attack_paths import (
    AttackPathDetail,
    AttackPathList,
    AttackPathSummary,
    PathEdgeRead,
    PathNodeRead,
)

PathSort = Literal["score_desc", "score_asc"]


@dataclass(frozen=True)
class AttackPathFilters:
    classification: PathClassification | None = None
    min_score: int | None = None
    start_identity_id: uuid.UUID | None = None
    target_resource_id: uuid.UUID | None = None
    sort: PathSort = "score_desc"
    limit: int = 200
    offset: int = 0


def _summary(path: AttackPath, start_name: str, target_name: str) -> AttackPathSummary:
    return AttackPathSummary(
        id=path.id,
        analysis_run_id=path.analysis_run_id,
        start_identity_id=path.start_identity_id,
        start_identity_name=start_name,
        target_resource_id=path.target_resource_id,
        target_resource_name=target_name,
        classification=path.classification,
        risk_score=path.risk_score,
        severity=severity_for(path.risk_score),
        step_count=len(path.edges),
        summary=path.summary,
        created_at=path.created_at,
    )


def list_attack_paths(
    db: Session, run: AnalysisRun, filters: AttackPathFilters
) -> AttackPathList:
    conditions = [AttackPath.analysis_run_id == run.id]
    if filters.classification is not None:
        conditions.append(AttackPath.classification == filters.classification)
    if filters.min_score is not None:
        conditions.append(AttackPath.risk_score >= filters.min_score)
    if filters.start_identity_id is not None:
        conditions.append(AttackPath.start_identity_id == filters.start_identity_id)
    if filters.target_resource_id is not None:
        conditions.append(AttackPath.target_resource_id == filters.target_resource_id)
    total = db.scalar(select(func.count()).select_from(AttackPath).where(*conditions)) or 0
    score_order = (
        AttackPath.risk_score.desc() if filters.sort == "score_desc" else AttackPath.risk_score
    )
    rows = db.execute(
        select(AttackPath, Identity.name, Resource.name)
        .join(Identity, AttackPath.start_identity_id == Identity.id)
        .join(Resource, AttackPath.target_resource_id == Resource.id)
        .where(*conditions)
        .order_by(score_order, Identity.name, Resource.name, AttackPath.fingerprint)
        .limit(filters.limit)
        .offset(filters.offset)
    ).all()
    return AttackPathList(
        total=total,
        items=[_summary(path, start_name, target_name) for path, start_name, target_name in rows],
    )


def get_attack_path(db: Session, run: AnalysisRun, path_id: uuid.UUID) -> AttackPathDetail | None:
    row = db.execute(
        select(AttackPath, Identity.name, Resource.name)
        .join(Identity, AttackPath.start_identity_id == Identity.id)
        .join(Resource, AttackPath.target_resource_id == Resource.id)
        .where(AttackPath.id == path_id, AttackPath.analysis_run_id == run.id)
    ).first()
    if row is None:
        return None
    path, start_name, target_name = row
    return AttackPathDetail(
        **_summary(path, start_name, target_name).model_dump(),
        raw_score=sum(factor["points"] for factor in path.risk_factors),
        risk_factors=[RiskFactorRead(**factor) for factor in path.risk_factors],
        nodes=[PathNodeRead(**node) for node in path.nodes],
        edges=[PathEdgeRead(**edge) for edge in path.edges],
        evidence=path.evidence,
    )