from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AnalysisRun, Environment, Finding, Identity, Resource, User
from app.models.enums import AnalysisStatus, FindingStatus, Severity
from app.schemas.dashboard import DashboardFinding, DashboardRead, DashboardRun

RECENT_RUNS = 5
TOP_FINDINGS = 8


def build_dashboard(db: Session, user: User) -> DashboardRead:
    environment_count = (
        db.scalar(
            select(func.count()).select_from(Environment).where(Environment.owner_id == user.id)
        )
        or 0
    )
    latest_runs = list(
        db.scalars(
            select(AnalysisRun)
            .join(Environment, AnalysisRun.environment_id == Environment.id)
            .where(
                Environment.owner_id == user.id,
                AnalysisRun.status == AnalysisStatus.COMPLETED,
            )
            .distinct(AnalysisRun.environment_id)
            .order_by(AnalysisRun.environment_id, AnalysisRun.started_at.desc(), AnalysisRun.id)
        )
    )
    recent = db.execute(
        select(AnalysisRun, Environment.name)
        .join(Environment, AnalysisRun.environment_id == Environment.id)
        .where(Environment.owner_id == user.id)
        .order_by(AnalysisRun.started_at.desc(), AnalysisRun.id)
        .limit(RECENT_RUNS)
    ).all()
    recent_runs = [
        DashboardRun(
            run_id=run.id,
            environment_id=run.environment_id,
            environment_name=name,
            started_at=run.started_at,
            status=run.status,
            finding_count=run.finding_count,
            attack_path_count=run.attack_path_count,
        )
        for run, name in recent
    ]

    identity_count = sensitive_count = open_count = high_count = 0
    top_findings: list[DashboardFinding] = []
    if latest_runs:
        run_ids = [run.id for run in latest_runs]
        import_ids = [run.import_id for run in latest_runs]
        identity_count = (
            db.scalar(
                select(func.count()).select_from(Identity).where(Identity.import_id.in_(import_ids))
            )
            or 0
        )
        sensitive_count = (
            db.scalar(
                select(func.count())
                .select_from(Resource)
                .where(Resource.import_id.in_(import_ids), Resource.is_sensitive.is_(True))
            )
            or 0
        )
        open_count = (
            db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(Finding.analysis_run_id.in_(run_ids), Finding.status == FindingStatus.OPEN)
            )
            or 0
        )
        high_count = (
            db.scalar(
                select(func.count())
                .select_from(Finding)
                .where(
                    Finding.analysis_run_id.in_(run_ids),
                    Finding.severity.in_([Severity.CRITICAL, Severity.HIGH]),
                )
            )
            or 0
        )
        rows = db.execute(
            select(Finding, AnalysisRun.environment_id, Environment.name)
            .join(AnalysisRun, Finding.analysis_run_id == AnalysisRun.id)
            .join(Environment, AnalysisRun.environment_id == Environment.id)
            .where(Finding.analysis_run_id.in_(run_ids))
            .order_by(Finding.risk_score.desc(), Finding.rule_id, Finding.title, Finding.id)
            .limit(TOP_FINDINGS)
        ).all()
        top_findings = [
            DashboardFinding(
                finding_id=finding.id,
                run_id=finding.analysis_run_id,
                environment_id=environment_id,
                environment_name=name,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                risk_score=finding.risk_score,
            )
            for finding, environment_id, name in rows
        ]
    return DashboardRead(
        environment_count=environment_count,
        analyzed_environment_count=len(latest_runs),
        identity_count=identity_count,
        sensitive_resource_count=sensitive_count,
        open_finding_count=open_count,
        critical_high_finding_count=high_count,
        attack_path_count=sum(run.attack_path_count for run in latest_runs),
        recent_runs=recent_runs,
        top_findings=top_findings,
    )