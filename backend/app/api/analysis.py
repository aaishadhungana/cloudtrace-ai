import uuid
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query, status

from app.api.deps import DbSession, OwnedEnvironment, OwnedRun
from app.models.enums import FindingStatus, Severity
from app.schemas.analysis import (
    AnalysisRunCreate,
    AnalysisRunDetail,
    AnalysisRunRead,
    FindingDetail,
    FindingList,
    IdentityDetail,
    IdentitySummary,
)
from app.services.analysis import (
    AnalysisFailedError,
    ImportNotFoundError,
    NoImportError,
    resolve_import,
    run_analysis,
)
from app.services.analysis_queries import (
    FindingFilters,
    SortName,
    get_finding,
    get_identity_detail,
    list_findings,
    list_identities,
    list_runs,
    run_detail,
    run_read,
    severity_counts,
)

router = APIRouter(prefix="/environments/{environment_id}/analysis-runs", tags=["analysis"])

RULE_ID_PATTERN = r"^CT-[A-Z]{2,6}-[0-9]{3}$"


@router.post("", response_model=AnalysisRunRead, status_code=status.HTTP_201_CREATED)
def start_analysis(
    environment: OwnedEnvironment, db: DbSession, payload: AnalysisRunCreate | None = None
) -> AnalysisRunRead:
    try:
        import_record = resolve_import(db, environment, payload.import_id if payload else None)
    except ImportNotFoundError as error:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Import not found") from error
    except NoImportError as error:
        raise HTTPException(
            status.HTTP_409_CONFLICT, "Import a configuration before running an analysis"
        ) from error
    try:
        run = run_analysis(db, environment, import_record)
    except AnalysisFailedError as error:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Analysis failed") from error
    return run_read(run, severity_counts(db, [run.id])[run.id])


@router.get("", response_model=list[AnalysisRunRead])
def read_runs(environment: OwnedEnvironment, db: DbSession) -> list[AnalysisRunRead]:
    return list_runs(db, environment.id)


@router.get("/{run_id}", response_model=AnalysisRunDetail)
def read_run(run: OwnedRun, db: DbSession) -> AnalysisRunDetail:
    return run_detail(db, run)


@router.get("/{run_id}/findings", response_model=FindingList)
def read_findings(
    run: OwnedRun,
    db: DbSession,
    severity: Severity | None = None,
    rule_id: Annotated[str | None, Query(pattern=RULE_ID_PATTERN)] = None,
    finding_status: Annotated[FindingStatus | None, Query(alias="status")] = None,
    identity_id: uuid.UUID | None = None,
    resource_id: uuid.UUID | None = None,
    sort: SortName = "score_desc",
    limit: Annotated[int, Query(ge=1, le=500)] = 200,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> FindingList:
    filters = FindingFilters(
        severity=severity,
        rule_id=rule_id,
        status=finding_status,
        identity_id=identity_id,
        resource_id=resource_id,
        sort=sort,
        limit=limit,
        offset=offset,
    )
    return list_findings(db, run, filters)


@router.get("/{run_id}/findings/{finding_id}", response_model=FindingDetail)
def read_finding(run: OwnedRun, finding_id: uuid.UUID, db: DbSession) -> FindingDetail:
    finding = get_finding(db, run, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found")
    return finding


@router.get("/{run_id}/identities", response_model=list[IdentitySummary])
def read_identities(run: OwnedRun, db: DbSession) -> list[IdentitySummary]:
    return list_identities(db, run)


@router.get("/{run_id}/identities/{identity_id}", response_model=IdentityDetail)
def read_identity(run: OwnedRun, identity_id: uuid.UUID, db: DbSession) -> IdentityDetail:
    identity = get_identity_detail(db, run, identity_id)
    if identity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Identity not found")
    return identity