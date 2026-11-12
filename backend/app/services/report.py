from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnalysisRun, Environment, Finding, Identity, ImportRecord, Resource
from app.models.enums import AISubjectType
from app.schemas.report import (
    ReportEnvironment,
    ReportFinding,
    ReportPath,
    ReportRead,
    ReportScope,
)
from app.services.ai_analysis import RUN_KEY, read_stored
from app.services.analysis_queries import run_detail
from app.services.attack_path_queries import AttackPathFilters, list_attack_paths

REPORT_FINDINGS = 25
REPORT_PATHS = 15


def build_report(db: Session, environment: Environment, run: AnalysisRun) -> ReportRead:
    detail = run_detail(db, run)
    record = db.get(ImportRecord, run.import_id)
    metadata = record.sanitized_metadata if record else {}
    rows = db.execute(
        select(Finding, Identity.name, Resource.name)
        .outerjoin(Identity, Finding.identity_id == Identity.id)
        .outerjoin(Resource, Finding.resource_id == Resource.id)
        .where(Finding.analysis_run_id == run.id)
        .order_by(Finding.risk_score.desc(), Finding.rule_id, Finding.title, Finding.id)
        .limit(REPORT_FINDINGS)
    ).all()
    paths = list_attack_paths(db, run, AttackPathFilters(limit=REPORT_PATHS))
    return ReportRead(
        generated_at=datetime.now(timezone.utc),
        environment=ReportEnvironment(
            name=environment.name,
            cloud_provider=environment.cloud_provider,
            description=environment.description,
        ),
        scope=ReportScope(
            run_id=run.id,
            started_at=run.started_at,
            completed_at=run.completed_at,
            analysis_version=run.analysis_version,
            import_source=detail.import_source,
            import_created_at=detail.import_created_at,
            identity_count=metadata.get("identity_count", 0),
            resource_count=metadata.get("resource_count", 0),
            sensitive_resource_count=metadata.get("sensitive_resource_count", 0),
            policy_count=metadata.get("policy_count", 0),
            statement_count=metadata.get("statement_count", 0),
        ),
        finding_total=run.finding_count,
        severity_counts=detail.severity_counts,
        findings=[
            ReportFinding(
                id=finding.id,
                rule_id=finding.rule_id,
                title=finding.title,
                severity=finding.severity,
                risk_score=finding.risk_score,
                identity_name=identity_name,
                resource_name=resource_name,
                explanation=finding.explanation,
                remediation=finding.remediation,
            )
            for finding, identity_name, resource_name in rows
        ],
        findings_not_shown=max(0, run.finding_count - len(rows)),
        attack_path_total=paths.total,
        attack_paths=[
            ReportPath(
                id=item.id,
                summary=item.summary,
                classification=item.classification,
                severity=item.severity,
                risk_score=item.risk_score,
                start=item.start_identity_name,
                target=item.target_resource_name,
                step_count=item.step_count,
            )
            for item in paths.items
        ],
        attack_paths_not_shown=max(0, paths.total - len(paths.items)),
        paths_incomplete=run.paths_incomplete,
        ai_summary=read_stored(db, run, AISubjectType.SUMMARY, RUN_KEY),
        limitations=detail.limitations,
    )


def _md(value: object) -> str:
    text = " ".join(str(value).split())
    for character, replacement in (
        ("&", "&amp;"),
        ("<", "&lt;"),
        (">", "&gt;"),
        ("`", "'"),
        ("|", "/"),
    ):
        text = text.replace(character, replacement)
    return text


def render_markdown(report: ReportRead) -> str:
    scope = report.scope
    counts = report.severity_counts
    lines = [
        "# CloudTrace AI security report",
        "",
        f"Generated: {report.generated_at.isoformat()}",
        "",
        "## Environment",
        "",
        f"- Name: {_md(report.environment.name)}",
        f"- Cloud provider: {report.environment.cloud_provider.value.upper()}",
    ]
    if report.environment.description:
        lines.append(f"- Description: {_md(report.environment.description)}")
    lines += [
        "",
        "## Analysis scope",
        "",
        f"- Analysis run: {scope.run_id}",
        f"- Started: {scope.started_at.isoformat()}",
        f"- Engine version: {_md(scope.analysis_version)}",
        f"- Import: {_md(scope.import_source)} (imported {scope.import_created_at.isoformat()})",
        f"- Modeled: {scope.identity_count} identities, {scope.resource_count} resources "
        f"({scope.sensitive_resource_count} sensitive), {scope.policy_count} policies, "
        f"{scope.statement_count} statements",
        "",
        "## Summary",
        "",
        f"- Findings: {report.finding_total} (critical {counts.critical}, high {counts.high}, "
        f"medium {counts.medium}, low {counts.low}, info {counts.info})",
        f"- Attack paths: {report.attack_path_total}",
        "",
        "## Highest-priority findings",
        "",
    ]
    if not report.findings:
        lines += ["No findings were reported.", ""]
    for index, finding in enumerate(report.findings, start=1):
        affected = ", ".join(
            _md(name) for name in (finding.identity_name, finding.resource_name) if name
        )
        lines += [
            f"### {index}. {finding.severity.value.upper()} {finding.risk_score}: {_md(finding.title)}",
            "",
            f"- Rule: {finding.rule_id}",
            f"- Affected: {affected or 'not specified'}",
            f"- What was detected: {_md(finding.explanation)}",
            f"- Remediation: {_md(finding.remediation)}",
            "",
        ]
    if report.findings_not_shown:
        lines += [f"{report.findings_not_shown} more findings are not listed here.", ""]
    lines += ["## Attack paths", ""]
    if not report.attack_paths:
        lines += [
            "No attack paths were found. This does not prove that sensitive resources are safe.",
            "",
        ]
    for path in report.attack_paths:
        lines.append(
            f"- {path.severity.value.upper()} {path.risk_score} ({path.classification.value}): "
            f"{_md(path.summary)}"
        )
    if report.attack_paths:
        lines.append("")
    if report.attack_paths_not_shown:
        lines += [f"{report.attack_paths_not_shown} more attack paths are not listed here.", ""]
    if report.paths_incomplete:
        lines += [
            "Attack-path discovery reached a limit, so the list above may be incomplete.",
            "",
        ]
    if report.ai_summary is not None:
        content = report.ai_summary.content
        lines += [
            "## AI-generated summary (not verified evidence)",
            "",
            _md(report.ai_summary.notice),
            "",
            _md(content.get("overview", "")),
            "",
        ]
        for priority in content.get("priorities", []):
            lines.append(
                f"- {_md(priority.get('title', ''))}: {_md(priority.get('why', ''))} "
                f"Recommended: {_md(priority.get('recommended_action', ''))}"
            )
        for caveat in content.get("caveats", []):
            lines.append(f"- Caveat: {_md(caveat)}")
        lines.append("")
    lines += ["## Limitations", ""]
    lines += [f"- {_md(item)}" for item in report.limitations]
    return "\n".join(lines) + "\n"