from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from app.api.deps import DbSession, OwnedEnvironment
from app.core.config import get_settings
from app.ingest.parser import ImportRejectedError
from app.ingest.pipeline import process_import
from app.models import ImportRecord
from app.schemas.imports import ImportRead
from app.services.imports import list_imports, save_import

router = APIRouter(prefix="/environments/{environment_id}/imports", tags=["imports"])

SOURCE_PATTERN = r"^[A-Za-z0-9._() -]+$"


async def read_limited_body(request: Request) -> bytes:
    content_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if content_type != "application/json":
        raise HTTPException(
            status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json"
        )
    max_bytes = get_settings().import_max_bytes
    too_large = HTTPException(
        status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
        f"Import exceeds the {max_bytes} byte limit",
    )
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > max_bytes:
        raise too_large
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > max_bytes:
            raise too_large
        chunks.append(chunk)
    return b"".join(chunks)


@router.post("", response_model=ImportRead, status_code=status.HTTP_201_CREATED)
def create_import(
    environment: OwnedEnvironment,
    body: Annotated[bytes, Depends(read_limited_body)],
    db: DbSession,
    source: Annotated[str, Query(min_length=1, max_length=255, pattern=SOURCE_PATTERN)] = "api-upload",
) -> ImportRecord:
    try:
        normalized = process_import(body)
    except ImportRejectedError as error:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={
                "message": "Import validation failed",
                "issues": [issue.model_dump() for issue in error.issues],
            },
        ) from error
    return save_import(db, environment, normalized, source)


@router.get("", response_model=list[ImportRead])
def read_imports(environment: OwnedEnvironment, db: DbSession) -> list[ImportRecord]:
    return list_imports(db, environment.id)