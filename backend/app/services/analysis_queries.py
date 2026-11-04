import uuid
from collections import defaultdict
from dataclasses import dataclass
from typing import Literal

from sqlalchemy import func, select
from sqlalchemy.orm import Session, aliased

from app.engine.analyzer import LIMITATIONS
from app.engine.scoring import severity_for
from app.models import (
    AnalysisRun,
    Finding,
    Identity,
    ImportRecord,
    PermissionRelationship,
    Policy,
    Resource,
)
from app.models.enums import Effect, FindingStatus, Severity
from app.schemas.analysis import (
    AccessEntry,
    AnalysisRunDetail,
    AnalysisRunRead,
    FindingDetail,
    FindingList,
    FindingSummary,
    IdentityDetail,
    IdentitySummary,
    PolicyRead,
    RiskFactorRead,
    SeverityCounts,
)

SortName = Literal["score_desc", "score_asc", "rule"]

ORDERINGS = {
    "score_desc": (Finding.risk_score.desc(), Finding.rule_id, Finding.title, Finding.id),
    "score_asc": (Finding.risk_score, Finding.rule_id, Finding.title, Finding.id),
    "rule": (Finding.rule_id, Finding.risk_score.desc(), Finding.title, Finding.id),
}


@dataclass(frozen=True)
class FindingFilters:
    severity: Severity | None = None
    rule_id: str | None = None
    status: FindingStatus | None = None
    identity_id: uuid.UUID | None = None
    resource_id: uuid.UUID | None = None
    sort: SortName = "score_desc"
    limit: int = 200
    offset: int = 0


def severity_counts(db: Session, run_ids: list[uuid.UUID]) -> dict[uuid.UUID, SeverityCounts]:
    counts = {run_id: SeverityCounts() for run_id in run_ids}
    if not run_ids:
        return counts
    rows = db.execute(
        select(Finding.analysis_run_id, Finding.severity, func.count())
        .where(Finding.analysis_run_id.in_(run_ids))
        .group_by(Finding.analysis_run_id, Finding.severity)
    )
    for run_id, severity, count in rows:
        setattr(counts[run_id], severity.value, count)
    return counts


def run_read(run: AnalysisRun, counts: SeverityCounts) -> AnalysisRunRead:
    return AnalysisRunRead(
        id=run.id,
        environment_id=run.environment_id,
        import_id=run.import_id,
        status=run.status,
        analysis_version=run.analysis_version,
        started_at=run.started_at,
        completed_at=run.completed_at,
        finding_count=run.finding_count,
        severity_counts=counts,
    )


def list_runs(db: Session, environment_id: uuid.UUID) -> list[AnalysisRunRead]:
    runs = list(
        db.scalars(
            select(AnalysisRun)
            .where(AnalysisRun.environment_id == environment_id)
            .order_by(AnalysisRun.started_at.desc(), AnalysisRun.id)
        )
    )
    counts = severity_counts(db, [run.id for run in runs])
    return [run_read(run, counts[run.id]) for run in runs]


def run_detail(db: Session, run: AnalysisRun) -> AnalysisRunDetail:
    record = db.get(ImportRecord, run.import_id)
    counts = severity_counts(db, [run.id])[run.id]
    return AnalysisRunDetail(
        **run_read(run, counts).model_dump(),
        limitations=list(LIMITATIONS),
        import_source=record.import_source if record else "unknown",
        import_created_at=record.created_at if record else run.started_at,
    )


def _finding_summary(
    finding: Finding, identity_name: str | None, resource_name: str | None
) -> FindingSummary:
    return FindingSummary(
        id=finding.id,
        analysis_run_id=finding.analysis_run_id,
        rule_id=finding.rule_id,
        finding_type=finding.finding_type,
        title=finding.title,
        severity=finding.severity,
        risk_score=finding.risk_score,
        status=finding.status,
        identity_id=finding.identity_id,
        identity_name=identity_name,
        resource_id=finding.resource_id,
        resource_name=resource_name,
        created_at=finding.created_at,
    )


def list_findings(db: Session, run: AnalysisRun, filters: FindingFilters) -> FindingList:
    conditions = [Finding.analysis_run_id == run.id]
    if filters.severity is not None:
        conditions.append(Finding.severity == filters.severity)
    if filters.rule_id is not None:
        conditions.append(Finding.rule_id == filters.rule_id)
    if filters.status is not None:
        conditions.append(Finding.status == filters.status)
    if filters.identity_id is not None:
        conditions.append(Finding.identity_id == filters.identity_id)
    if filters.resource_id is not None:
        conditions.append(Finding.resource_id == filters.resource_id)
    total = db.scalar(select(func.count()).select_from(Finding).where(*conditions)) or 0
    rows = db.execute(
        select(Finding, Identity.name, Resource.name)
        .outerjoin(Identity, Finding.identity_id == Identity.id)
        .outerjoin(Resource, Finding.resource_id == Resource.id)
        .where(*conditions)
        .order_by(*ORDERINGS[filters.sort])
        .limit(filters.limit)
        .offset(filters.offset)
    ).all()
    return FindingList(
        total=total,
        items=[_finding_summary(finding, identity, resource) for finding, identity, resource in rows],
    )


def get_finding(db: Session, run: AnalysisRun, finding_id: uuid.UUID) -> FindingDetail | None:
    row = db.execute(
        select(Finding, Identity.name, Identity.external_id, Resource.name, Resource.external_id)
        .outerjoin(Identity, Finding.identity_id == Identity.id)
        .outerjoin(Resource, Finding.resource_id == Resource.id)
        .where(Finding.id == finding_id, Finding.analysis_run_id == run.id)
    ).first()
    if row is None:
        return None
    finding, identity_name, identity_arn, resource_name, resource_arn = row
    summary = _finding_summary(finding, identity_name, resource_name)
    return FindingDetail(
        **summary.model_dump(),
        identity_arn=identity_arn,
        resource_arn=resource_arn,
        explanation=finding.explanation,
        remediation=finding.remediation,
        raw_score=sum(factor["points"] for factor in finding.risk_factors),
        risk_factors=[RiskFactorRead(**factor) for factor in finding.risk_factors],
        evidence=finding.evidence,
    )


def _identity_summaries(
    db: Session, run: AnalysisRun, only: uuid.UUID | None = None
) -> list[IdentitySummary]:
    identity_query = (
        select(Identity)
        .where(Identity.import_id == run.import_id)
        .order_by(Identity.name, Identity.external_id)
    )
    if only is not None:
        identity_query = identity_query.where(Identity.id == only)
    identities = list(db.scalars(identity_query))
    if not identities:
        return []

    policy_names = dict(
        db.execute(select(Policy.external_id, Policy.name).where(Policy.import_id == run.import_id))
        .tuples()
        .all()
    )
    finding_stats = {
        identity_id: (count, top)
        for identity_id, count, top in db.execute(
            select(Finding.identity_id, func.count(), func.max(Finding.risk_score))
            .where(Finding.analysis_run_id == run.id, Finding.identity_id.is_not(None))
            .group_by(Finding.identity_id)
        )
    }
    sensitive_ids = set(
        db.scalars(
            select(Resource.id).where(
                Resource.import_id == run.import_id, Resource.is_sensitive.is_(True)
            )
        )
    )
    reach_query = select(
        PermissionRelationship.source_identity_id,
        PermissionRelationship.target_identity_id,
        PermissionRelationship.target_resource_id,
    ).where(
        PermissionRelationship.analysis_run_id == run.id,
        PermissionRelationship.effect == Effect.ALLOW,
    )
    if only is not None:
        reach_query = reach_query.where(PermissionRelationship.source_identity_id == only)
    reachable: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    sensitive: dict[uuid.UUID, set[uuid.UUID]] = defaultdict(set)
    for source_id, target_identity_id, target_resource_id in db.execute(reach_query):
        reachable[source_id].add(target_identity_id or target_resource_id)
        if target_resource_id in sensitive_ids:
            sensitive[source_id].add(target_resource_id)

    summaries = []
    for identity in identities:
        count, top = finding_stats.get(identity.id, (0, None))
        summaries.append(
            IdentitySummary(
                id=identity.id,
                arn=identity.external_id,
                name=identity.name,
                identity_type=identity.identity_type,
                account_id=identity.account_id,
                policy_names=[
                    policy_names[policy_id]
                    for policy_id in identity.attributes.get("policy_ids", [])
                    if policy_id in policy_names
                ],
                finding_count=count,
                max_risk_score=top,
                risk_level=severity_for(top) if top is not None else None,
                reachable_target_count=len(reachable.get(identity.id, ())),
                sensitive_target_count=len(sensitive.get(identity.id, ())),
            )
        )
    return summaries


def list_identities(db: Session, run: AnalysisRun) -> list[IdentitySummary]:
    return _identity_summaries(db, run)


def _access_entries(db: Session, run: AnalysisRun, identity: Identity) -> list[AccessEntry]:
    target_identity = aliased(Identity)
    rows = db.execute(
        select(PermissionRelationship, target_identity, Resource)
        .outerjoin(
            target_identity, PermissionRelationship.target_identity_id == target_identity.id
        )
        .outerjoin(Resource, PermissionRelationship.target_resource_id == Resource.id)
        .where(
            PermissionRelationship.analysis_run_id == run.id,
            PermissionRelationship.source_identity_id == identity.id,
        )
    ).all()
    entries = []
    for relationship, identity_target, resource_target in rows:
        target = identity_target if identity_target is not None else resource_target
        entries.append(
            AccessEntry(
                target_kind="identity" if identity_target is not None else "resource",
                target_id=target.id,
                target_arn=target.external_id,
                target_name=target.name,
                is_sensitive=resource_target.is_sensitive if resource_target is not None else False,
                relationship_type=relationship.relationship_type,
                effect=relationship.effect,
                decision=relationship.decision,
                actions=list(relationship.evidence.get("actions", [])),
                notes=list(relationship.conditions.get("notes", [])),
                statements=list(relationship.evidence.get("statements", [])),
            )
        )
    entries.sort(key=lambda entry: (entry.target_name, entry.relationship_type.value))
    return entries


def get_identity_detail(
    db: Session, run: AnalysisRun, identity_id: uuid.UUID
) -> IdentityDetail | None:
    summaries = _identity_summaries(db, run, identity_id)
    if not summaries:
        return None
    identity = db.get(Identity, identity_id)
    policy_ids = identity.attributes.get("policy_ids", [])
    policies = (
        [
            PolicyRead(id=item.external_id, name=item.name, statements=item.statements)
            for item in db.scalars(
                select(Policy)
                .where(Policy.import_id == run.import_id, Policy.external_id.in_(policy_ids))
                .order_by(Policy.name)
            )
        ]
        if policy_ids
        else []
    )
    findings = list_findings(db, run, FindingFilters(identity_id=identity_id)).items
    return IdentityDetail(
        **summaries[0].model_dump(),
        policies=policies,
        trust_policy=identity.attributes.get("trust_policy"),
        access=_access_entries(db, run, identity),
        findings=findings,
    )