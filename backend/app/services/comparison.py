import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnalysisRun, AttackPath, Finding, Identity, ImportRecord, Resource
from app.schemas.comparison import (
    ComparedFinding,
    ComparedPath,
    ComparisonStatus,
    RunComparison,
    RunSide,
    StatusCounts,
)
from app.services.analysis_queries import severity_counts

STATUS_ORDER = {
    ComparisonStatus.NEW: 0,
    ComparisonStatus.PERSISTING: 1,
    ComparisonStatus.NO_LONGER_DETECTED: 2,
    ComparisonStatus.NOT_COMPARABLE: 3,
}

NOT_SECURE_CAVEAT = (
    "Fewer findings or paths does not mean the environment is secure. The comparison only reflects "
    "the modeled permissions and the rules of the engine version used."
)


@dataclass(frozen=True)
class Item:
    row_id: uuid.UUID
    score: int
    subjects: frozenset[str]
    row: Any


def _import_arns(db: Session, import_id: uuid.UUID) -> set[str]:
    identities = db.scalars(select(Identity.external_id).where(Identity.import_id == import_id))
    resources = db.scalars(select(Resource.external_id).where(Resource.import_id == import_id))
    return set(identities) | set(resources)


def _finding_items(db: Session, run: AnalysisRun) -> dict[str, Item]:
    rows = db.execute(
        select(Finding, Identity.external_id, Resource.external_id)
        .outerjoin(Identity, Finding.identity_id == Identity.id)
        .outerjoin(Resource, Finding.resource_id == Resource.id)
        .where(Finding.analysis_run_id == run.id)
    ).all()
    return {
        finding.fingerprint: Item(
            finding.id,
            finding.risk_score,
            frozenset(arn for arn in (identity_arn, resource_arn) if arn),
            finding,
        )
        for finding, identity_arn, resource_arn in rows
    }


def _path_items(db: Session, run: AnalysisRun) -> dict[str, Item]:
    paths = db.scalars(select(AttackPath).where(AttackPath.analysis_run_id == run.id))
    return {
        path.fingerprint: Item(
            path.id,
            path.risk_score,
            frozenset(node["arn"] for node in path.nodes),
            path,
        )
        for path in paths
    }


def _classify(
    base: Item | None, target: Item | None, base_arns: set[str], target_arns: set[str]
) -> tuple[ComparisonStatus, str | None]:
    if base is not None and target is not None:
        reason = None
        if base.score != target.score:
            reason = f"Risk score changed from {base.score} to {target.score}."
        return ComparisonStatus.PERSISTING, reason
    if base is not None:
        missing = sorted(base.subjects - target_arns)
        if missing:
            return (
                ComparisonStatus.NOT_COMPARABLE,
                f"{', '.join(missing)} no longer exists in the target import, so this cannot be "
                "compared.",
            )
        return (
            ComparisonStatus.NO_LONGER_DETECTED,
            "The affected identities and resources are still in the target import, but the engine "
            "no longer reports this.",
        )
    assert target is not None
    if target.subjects - base_arns:
        return ComparisonStatus.NEW, "Involves an identity or resource that is not in the base import."
    return ComparisonStatus.NEW, None


def _counts(statuses: list[ComparisonStatus]) -> StatusCounts:
    return StatusCounts(**{status.value: statuses.count(status) for status in ComparisonStatus})


def _side(db: Session, run: AnalysisRun) -> RunSide:
    record = db.get(ImportRecord, run.import_id)
    counts = severity_counts(db, [run.id])[run.id]
    return RunSide(
        run_id=run.id,
        import_id=run.import_id,
        import_source=record.import_source if record else "unknown",
        started_at=run.started_at,
        analysis_version=run.analysis_version,
        finding_count=run.finding_count,
        high_risk_finding_count=counts.critical + counts.high,
        attack_path_count=run.attack_path_count,
        paths_incomplete=run.paths_incomplete,
        severity_counts=counts,
    )


def _caveats(
    base: RunSide, target: RunSide, finding_counts: StatusCounts, path_counts: StatusCounts
) -> list[str]:
    caveats = [NOT_SECURE_CAVEAT]
    if base.analysis_version != target.analysis_version:
        caveats.append(
            f"The runs used different analysis engine versions ({base.analysis_version} and "
            f"{target.analysis_version}), so some differences may come from engine changes and not "
            "from configuration changes."
        )
    if base.paths_incomplete or target.paths_incomplete:
        caveats.append(
            "Attack-path discovery reached a limit in at least one run, so path counts may be "
            "incomplete."
        )
    if finding_counts.not_comparable or path_counts.not_comparable:
        caveats.append(
            "Some items cannot be compared because their identity or resource no longer exists in "
            "the target import. Nothing can be concluded about them."
        )
    return caveats


def compare_runs(db: Session, base_run: AnalysisRun, target_run: AnalysisRun) -> RunComparison:
    base_arns = _import_arns(db, base_run.import_id)
    target_arns = _import_arns(db, target_run.import_id)

    base_findings = _finding_items(db, base_run)
    target_findings = _finding_items(db, target_run)
    findings: list[ComparedFinding] = []
    for fingerprint in base_findings.keys() | target_findings.keys():
        base = base_findings.get(fingerprint)
        target = target_findings.get(fingerprint)
        status, reason = _classify(base, target, base_arns, target_arns)
        row: Finding = (target or base).row
        findings.append(
            ComparedFinding(
                fingerprint=fingerprint,
                status=status,
                rule_id=row.rule_id,
                title=row.title,
                severity=row.severity,
                base_score=base.score if base else None,
                target_score=target.score if target else None,
                base_finding_id=base.row_id if base else None,
                target_finding_id=target.row_id if target else None,
                reason=reason,
            )
        )
    findings.sort(
        key=lambda item: (
            STATUS_ORDER[item.status],
            -(item.target_score if item.target_score is not None else item.base_score or 0),
            item.title,
            item.fingerprint,
        )
    )

    base_paths = _path_items(db, base_run)
    target_paths = _path_items(db, target_run)
    paths: list[ComparedPath] = []
    for fingerprint in base_paths.keys() | target_paths.keys():
        base = base_paths.get(fingerprint)
        target = target_paths.get(fingerprint)
        status, reason = _classify(base, target, base_arns, target_arns)
        row_path: AttackPath = (target or base).row
        paths.append(
            ComparedPath(
                fingerprint=fingerprint,
                status=status,
                summary=row_path.summary,
                classification=row_path.classification,
                base_score=base.score if base else None,
                target_score=target.score if target else None,
                base_path_id=base.row_id if base else None,
                target_path_id=target.row_id if target else None,
                reason=reason,
            )
        )
    paths.sort(
        key=lambda item: (
            STATUS_ORDER[item.status],
            -(item.target_score if item.target_score is not None else item.base_score or 0),
            item.summary,
            item.fingerprint,
        )
    )

    finding_counts = _counts([item.status for item in findings])
    path_counts = _counts([item.status for item in paths])
    base_side = _side(db, base_run)
    target_side = _side(db, target_run)
    return RunComparison(
        base=base_side,
        target=target_side,
        findings=findings,
        finding_counts=finding_counts,
        attack_paths=paths,
        path_counts=path_counts,
        caveats=_caveats(base_side, target_side, finding_counts, path_counts),
    )