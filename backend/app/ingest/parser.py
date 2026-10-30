from pydantic import BaseModel, ValidationError

from app.ingest import limits
from app.ingest.schema import ImportDocument

EXTRA_FIELD_MESSAGE = (
    "Unsupported or unknown field. CloudTrace AI rejects fields it does not model "
    "instead of ignoring them."
)


class ImportIssue(BaseModel):
    path: str
    message: str


class ImportRejectedError(Exception):
    def __init__(self, issues: list[ImportIssue]) -> None:
        super().__init__("Import rejected")
        self.issues = issues


def _format_path(location: tuple[int | str, ...]) -> str:
    path = ""
    for part in location:
        path += f"[{part}]" if isinstance(part, int) else f".{part}"
    return path.lstrip(".") or "$"


def _format_message(error_type: str, message: str) -> str:
    if error_type == "extra_forbidden":
        return EXTRA_FIELD_MESSAGE
    return message.removeprefix("Value error, ")


def issues_from_validation_error(error: ValidationError) -> list[ImportIssue]:
    details = error.errors(include_url=False, include_context=False, include_input=False)
    return [
        ImportIssue(
            path=_format_path(item["loc"]),
            message=_format_message(item["type"], item["msg"]),
        )
        for item in details[: limits.MAX_REPORTED_ISSUES]
    ]


def parse_document(body: bytes) -> ImportDocument:
    try:
        return ImportDocument.model_validate_json(body)
    except ValidationError as error:
        raise ImportRejectedError(issues_from_validation_error(error)) from error