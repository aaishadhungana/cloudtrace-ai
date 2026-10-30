import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ingest.normalize import NormalizedImport
from app.models import Environment, Identity, ImportRecord, Policy, Resource
from app.models.enums import ValidationStatus


def save_import(
    db: Session, environment: Environment, normalized: NormalizedImport, source: str
) -> ImportRecord:
    record = ImportRecord(
        environment_id=environment.id,
        import_source=source,
        schema_version=normalized.schema_version,
        validation_status=ValidationStatus.VALID,
        sanitized_metadata=normalized.metadata,
    )
    db.add(record)
    db.flush()
    db.add_all([Identity(import_id=record.id, **item) for item in normalized.identities])
    db.add_all([Resource(import_id=record.id, **item) for item in normalized.resources])
    db.add_all([Policy(import_id=record.id, **item) for item in normalized.policies])
    db.commit()
    db.refresh(record)
    return record


def list_imports(db: Session, environment_id: uuid.UUID) -> list[ImportRecord]:
    statement = (
        select(ImportRecord)
        .where(ImportRecord.environment_id == environment_id)
        .order_by(ImportRecord.created_at.desc())
    )
    return list(db.scalars(statement))