import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.ai.analyst import Analyst
from app.ai.errors import AIError
from app.ai.gemini import NOT_CONFIGURED_MESSAGE, get_analyst
from app.api.deps import DbSession, OwnedRun
from app.models.enums import AISubjectType
from app.schemas.ai import AIAnalysisRead, AIStatus
from app.services.ai_analysis import (
    RUN_KEY,
    analyze_attack_path,
    analyze_finding,
    analyze_summary,
    read_stored,
)
from app.services.analysis_queries import get_finding
from app.services.attack_path_queries import get_attack_path

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/environments/{environment_id}/analysis-runs/{run_id}/ai", tags=["ai"]
)

AnalystDep = Annotated[Analyst, Depends(get_analyst)]
Refresh = Annotated[bool, Query()]


def _http_error(error: AIError) -> HTTPException:
    logger.warning("AI analysis failed: %s", error.code)
    return HTTPException(
        status_code=error.http_status,
        detail={"message": error.message, "code": error.code},
    )


@router.get("/status", response_model=AIStatus)
def read_ai_status(run: OwnedRun, analyst: AnalystDep) -> AIStatus:
    if analyst.is_configured:
        return AIStatus(available=True, model=analyst.model_name, reason=None)
    return AIStatus(available=False, model=None, reason=NOT_CONFIGURED_MESSAGE)


@router.get("/findings/{finding_id}", response_model=AIAnalysisRead | None)
def read_finding_analysis(
    run: OwnedRun, finding_id: uuid.UUID, db: DbSession
) -> AIAnalysisRead | None:
    if get_finding(db, run, finding_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return read_stored(db, run, AISubjectType.FINDING, str(finding_id))


@router.post("/findings/{finding_id}", response_model=AIAnalysisRead)
def create_finding_analysis(
    run: OwnedRun,
    finding_id: uuid.UUID,
    db: DbSession,
    analyst: AnalystDep,
    refresh: Refresh = False,
) -> AIAnalysisRead:
    finding = get_finding(db, run, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    try:
        return analyze_finding(db, run, finding, analyst, refresh)
    except AIError as error:
        raise _http_error(error) from error


@router.get("/attack-paths/{path_id}", response_model=AIAnalysisRead | None)
def read_attack_path_analysis(
    run: OwnedRun, path_id: uuid.UUID, db: DbSession
) -> AIAnalysisRead | None:
    if get_attack_path(db, run, path_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attack path not found")
    return read_stored(db, run, AISubjectType.ATTACK_PATH, str(path_id))


@router.post("/attack-paths/{path_id}", response_model=AIAnalysisRead)
def create_attack_path_analysis(
    run: OwnedRun,
    path_id: uuid.UUID,
    db: DbSession,
    analyst: AnalystDep,
    refresh: Refresh = False,
) -> AIAnalysisRead:
    path = get_attack_path(db, run, path_id)
    if path is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attack path not found")
    try:
        return analyze_attack_path(db, run, path, analyst, refresh)
    except AIError as error:
        raise _http_error(error) from error


@router.get("/summary", response_model=AIAnalysisRead | None)
def read_summary_analysis(run: OwnedRun, db: DbSession) -> AIAnalysisRead | None:
    return read_stored(db, run, AISubjectType.SUMMARY, RUN_KEY)


@router.post("/summary", response_model=AIAnalysisRead)
def create_summary_analysis(
    run: OwnedRun, db: DbSession, analyst: AnalystDep, refresh: Refresh = False
) -> AIAnalysisRead:
    try:
        return analyze_summary(db, run, analyst, refresh)
    except AIError as error:
        raise _http_error(error) from error