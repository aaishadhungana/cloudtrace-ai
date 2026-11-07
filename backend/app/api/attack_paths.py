import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import DbSession, OwnedRun
from app.models.enums import PathClassification
from app.schemas.attack_paths import AttackPathDetail, AttackPathList
from app.services.attack_path_queries import (
    AttackPathFilters,
    PathSort,
    get_attack_path,
    list_attack_paths,
)

router = APIRouter(
    prefix="/environments/{environment_id}/analysis-runs/{run_id}/attack-paths",
    tags=["attack-paths"],
)


@router.get("", response_model=AttackPathList)
def read_attack_paths(
    run: OwnedRun,
    db: DbSession,
    classification: PathClassification | None = None,
    min_score: Annotated[int | None, Query(ge=0, le=100)] = None,
    start_identity_id: uuid.UUID | None = None,
    target_resource_id: uuid.UUID | None = None,
    sort: PathSort = "score_desc",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> AttackPathList:
    filters = AttackPathFilters(
        classification=classification,
        min_score=min_score,
        start_identity_id=start_identity_id,
        target_resource_id=target_resource_id,
        sort=sort,
        limit=limit,
        offset=offset,
    )
    return list_attack_paths(db, run, filters)


@router.get("/{path_id}", response_model=AttackPathDetail)
def read_attack_path(run: OwnedRun, path_id: uuid.UUID, db: DbSession) -> AttackPathDetail:
    path = get_attack_path(db, run, path_id)
    if path is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Attack path not found")
    return path