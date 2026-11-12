from fastapi import APIRouter

from app.api.deps import CurrentUser, DbSession
from app.schemas.dashboard import DashboardRead
from app.services.dashboard import build_dashboard

router = APIRouter(tags=["dashboard"])


@router.get("/dashboard", response_model=DashboardRead)
def read_dashboard(user: CurrentUser, db: DbSession) -> DashboardRead:
    return build_dashboard(db, user)