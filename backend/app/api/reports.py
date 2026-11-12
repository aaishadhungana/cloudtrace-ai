from fastapi import APIRouter, HTTPException, Response, status

from app.api.deps import DbSession, OwnedEnvironment, OwnedRun
from app.models.enums import AnalysisStatus
from app.schemas.report import ReportRead
from app.services.report import build_report, render_markdown

router = APIRouter(
    prefix="/environments/{environment_id}/analysis-runs/{run_id}/report", tags=["reports"]
)


def _completed_report(environment: OwnedEnvironment, run: OwnedRun, db: DbSession) -> ReportRead:
    if run.status != AnalysisStatus.COMPLETED:
        raise HTTPException(status.HTTP_409_CONFLICT, "The analysis run did not complete")
    return build_report(db, environment, run)


@router.get("", response_model=ReportRead)
def read_report(environment: OwnedEnvironment, run: OwnedRun, db: DbSession) -> ReportRead:
    return _completed_report(environment, run, db)


@router.get("/markdown")
def download_report(environment: OwnedEnvironment, run: OwnedRun, db: DbSession) -> Response:
    report = _completed_report(environment, run, db)
    return Response(
        content=render_markdown(report),
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="cloudtrace-report-{run.id}.md"'},
    )