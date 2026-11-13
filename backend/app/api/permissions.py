from typing import Annotated

from fastapi import APIRouter, Query

from app.api.deps import DbSession, OwnedRun
from app.schemas.permissions import PermissionList
from app.services.permissions import list_permissions

router = APIRouter(
    prefix="/environments/{environment_id}/analysis-runs/{run_id}/permissions",
    tags=["permissions"],
)


@router.get("", response_model=PermissionList)
def read_permissions(
    run: OwnedRun,
    db: DbSession,
    limit: Annotated[int, Query(ge=1, le=1000)] = 500,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> PermissionList:
    return list_permissions(db, run, limit, offset)