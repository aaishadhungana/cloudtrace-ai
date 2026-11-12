import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import DbSession, OwnedEnvironment
from app.models import AnalysisRun, Environment
from app.models.enums import AnalysisStatus
from app.schemas.comparison import RunComparison
from app.services.comparison import compare_runs

router = APIRouter(prefix="/environments/{environment_id}", tags=["comparison"])


def _run_in(db: Session, environment: Environment, run_id: uuid.UUID) -> AnalysisRun:
    run = db.scalar(
        select(AnalysisRun).where(
            AnalysisRun.id == run_id, AnalysisRun.environment_id == environment.id
        )
    )
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Analysis run not found")
    return run


@router.get("/comparison", response_model=RunComparison)
def compare(
    environment: OwnedEnvironment,
    db: DbSession,
    base_run_id: uuid.UUID,
    target_run_id: uuid.UUID,
) -> RunComparison:
    if base_run_id == target_run_id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "Choose two different analysis runs to compare"
        )
    base = _run_in(db, environment, base_run_id)
    target = _run_in(db, environment, target_run_id)
    if base.status != AnalysisStatus.COMPLETED or target.status != AnalysisStatus.COMPLETED:
        raise HTTPException(status.HTTP_409_CONFLICT, "Both analysis runs must be completed")
    return compare_runs(db, base, target)