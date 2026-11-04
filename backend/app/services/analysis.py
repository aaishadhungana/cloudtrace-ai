import logging
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.engine.analyzer import ANALYSIS_VERSION, analyze
from app.engine.evaluation import EffectiveRelationship
from app.engine.evidence import ref_summary, relationship_evidence, statement_evidence
from app.engine.models import TARGET_IDENTITY, Snapshot
from app.engine.rules.base import FindingDraft
from app.engine.snapshot import build_snapshot
from app.models import (
    AnalysisRun,
    Environment,
    Finding,
    Identity,
    ImportRecord,
    PermissionRelationship,
    Policy,
    Resource,
)
from app.models.enums import AnalysisStatus, Effect, FindingStatus, ValidationStatus

logger = logging.getLogger(__name__)


class NoImportError(Exception):
    pass


class ImportNotFoundError(Exception):
    pass


class AnalysisFailedError(Exception):
    pass


@dataclass(frozen=True)
class LoadedImport:
    identities: list[dict[str, Any]]
    resources: list[dict[str, Any]]
    policies: list[dict[str, Any]]
    identity_ids: dict[str, uuid.UUID]
    resource_ids: dict[str, uuid.UUID]


def resolve_import(
    db: Session, environment: Environment, import_id: uuid.UUID | None
) -> ImportRecord:
    if import_id is not None:
        record = db.scalar(
            select(ImportRecord).where(
                ImportRecord.id == import_id, ImportRecord.environment_id == environment.id
            )
        )
        if record is None:
            raise ImportNotFoundError
        return record
    record = db.scalar(
        select(ImportRecord)
        .where(
            ImportRecord.environment_id == environment.id,
            ImportRecord.validation_status == ValidationStatus.VALID,
        )
        .order_by(ImportRecord.created_at.desc())
        .limit(1)
    )
    if record is None:
        raise NoImportError
    return record


def _load_import(db: Session, import_id: uuid.UUID) -> LoadedImport:
    identity_rows = list(
        db.scalars(
            select(Identity).where(Identity.import_id == import_id).order_by(Identity.external_id)
        )
    )
    resource_rows = list(
        db.scalars(
            select(Resource).where(Resource.import_id == import_id).order_by(Resource.external_id)
        )
    )
    policy_rows = list(
        db.scalars(
            select(Policy).where(Policy.import_id == import_id).order_by(Policy.external_id)
        )
    )
    return LoadedImport(
        identities=[
            {
                "external_id": item.external_id,
                "name": item.name,
                "identity_type": item.identity_type,
                "account_id": item.account_id,
                "attributes": item.attributes,
            }
            for item in identity_rows
        ],
        resources=[
            {
                "external_id": item.external_id,
                "name": item.name,
                "resource_type": item.resource_type,
                "is_sensitive": item.is_sensitive,
                "attributes": item.attributes,
            }
            for item in resource_rows
        ],
        policies=[
            {"external_id": item.external_id, "name": item.name, "statements": item.statements}
            for item in policy_rows
        ],
        identity_ids={item.external_id: item.id for item in identity_rows},
        resource_ids={item.external_id: item.id for item in resource_rows},
    )


def _finding_row(
    run_id: uuid.UUID, draft: FindingDraft, loaded: LoadedImport
) -> Finding:
    return Finding(
        analysis_run_id=run_id,
        fingerprint=draft.fingerprint,
        rule_id=draft.rule_id,
        finding_type=draft.finding_type,
        severity=draft.assessment.severity,
        risk_score=draft.assessment.score,
        title=draft.title,
        identity_id=loaded.identity_ids.get(draft.identity_arn) if draft.identity_arn else None,
        resource_id=loaded.resource_ids.get(draft.resource_arn) if draft.resource_arn else None,
        evidence=draft.evidence,
        risk_factors=draft.assessment.factor_dicts(),
        explanation=draft.explanation,
        remediation=draft.remediation,
        status=FindingStatus.OPEN,
    )


def _relationship_row(
    run_id: uuid.UUID,
    snapshot: Snapshot,
    relationship: EffectiveRelationship,
    loaded: LoadedImport,
) -> PermissionRelationship:
    refs = list(
        dict.fromkeys(
            [*relationship.allow_refs, *relationship.deny_refs, *relationship.supporting_refs]
        )
    )
    conditional_statements = [
        {**ref_summary(ref), "conditions": snapshot.statement(ref).conditions}
        for ref in refs
        if snapshot.statement(ref).has_conditions
    ]
    targets_identity = relationship.target_kind == TARGET_IDENTITY
    return PermissionRelationship(
        analysis_run_id=run_id,
        source_identity_id=loaded.identity_ids[relationship.source_arn],
        target_identity_id=loaded.identity_ids[relationship.target_arn] if targets_identity else None,
        target_resource_id=None if targets_identity else loaded.resource_ids[relationship.target_arn],
        relationship_type=relationship.relationship_type,
        effect=Effect(relationship.effect),
        decision=relationship.decision,
        conditions={"statements": conditional_statements, "notes": list(relationship.notes)},
        evidence={
            **relationship_evidence(relationship),
            "statements": [statement_evidence(snapshot, ref) for ref in refs],
        },
    )


def run_analysis(db: Session, environment: Environment, import_record: ImportRecord) -> AnalysisRun:
    run = AnalysisRun(
        environment_id=environment.id,
        import_id=import_record.id,
        status=AnalysisStatus.RUNNING,
        analysis_version=ANALYSIS_VERSION,
    )
    db.add(run)
    db.commit()
    run_id = run.id
    try:
        loaded = _load_import(db, import_record.id)
        snapshot = build_snapshot(loaded.identities, loaded.resources, loaded.policies)
        result = analyze(snapshot)
        db.add_all([_finding_row(run_id, draft, loaded) for draft in result.findings])
        db.add_all(
            [
                _relationship_row(run_id, snapshot, relationship, loaded)
                for relationship in result.relationships
            ]
        )
        run.status = AnalysisStatus.COMPLETED
        run.completed_at = datetime.now(timezone.utc)
        run.finding_count = len(result.findings)
        db.commit()
    except Exception as error:
        db.rollback()
        logger.exception("Analysis run %s failed", run_id)
        failed = db.get(AnalysisRun, run_id)
        if failed is not None:
            failed.status = AnalysisStatus.FAILED
            failed.completed_at = datetime.now(timezone.utc)
            db.commit()
        raise AnalysisFailedError from error
    db.refresh(run)
    return run