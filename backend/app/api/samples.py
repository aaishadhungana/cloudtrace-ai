from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Response, status

from app.api.deps import get_current_user
from app.samples.catalog import list_samples, read_sample
from app.schemas.samples import SampleRead

router = APIRouter(
    prefix="/samples", tags=["samples"], dependencies=[Depends(get_current_user)]
)


@router.get("", response_model=list[SampleRead])
def read_sample_catalog() -> list[SampleRead]:
    return [
        SampleRead(name=item.name, title=item.title, description=item.description)
        for item in list_samples()
    ]


@router.get("/{name}")
def read_sample_document(
    name: Annotated[str, Path(pattern=r"^[a-z0-9-]{1,64}$")],
) -> Response:
    content = read_sample(name)
    if content is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sample not found")
    return Response(content=content, media_type="application/json")