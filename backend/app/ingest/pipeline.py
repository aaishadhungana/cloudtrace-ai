from app.ingest.normalize import NormalizedImport, normalize_document
from app.ingest.parser import ImportRejectedError, parse_document
from app.ingest.semantic import validate_semantics


def process_import(body: bytes) -> NormalizedImport:
    document = parse_document(body)
    issues = validate_semantics(document)
    if issues:
        raise ImportRejectedError(issues)
    return normalize_document(document, body)