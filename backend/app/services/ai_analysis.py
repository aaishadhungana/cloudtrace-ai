import hashlib
import json
import uuid
from collections.abc import Callable
from datetime import datetime, timezone

from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.ai.analyst import Analyst
from app.ai.errors import AIInvalidResponseError
from app.ai.prompts import (
    PROMPT_VERSION,
    SYSTEM_INSTRUCTION,
    attack_path_payload,
    finding_payload,
    fit_to_budget,
    summary_payload,
)
from app.ai.sanitize import sanitize_payload
from app.ai.schemas import (
    AttackPathAnalysisOutput,
    FindingAnalysisOutput,
    SecuritySummaryOutput,
)
from app.core.config import get_settings
from app.models import AIAnalysis, AnalysisRun
from app.models.enums import AISubjectType
from app.schemas.ai import AIAnalysisRead
from app.schemas.analysis import FindingDetail
from app.schemas.attack_paths import AttackPathDetail
from app.services.analysis_queries import FindingFilters, list_findings, run_detail
from app.services.attack_path_queries import AttackPathFilters, list_attack_paths

RUN_KEY = "run"
SUMMARY_FINDINGS = 10
SUMMARY_PATHS = 5


def to_read(analysis: AIAnalysis, cached: bool) -> AIAnalysisRead:
    return AIAnalysisRead(
        subject_type=analysis.subject_type,
        subject_id=None if analysis.subject_key == RUN_KEY else uuid.UUID(analysis.subject_key),
        model=analysis.model,
        generated_at=analysis.generated_at,
        cached=cached,
        content=analysis.content,
    )


def _find_stored(
    db: Session, run: AnalysisRun, subject_type: AISubjectType, subject_key: str
) -> AIAnalysis | None:
    return db.scalar(
        select(AIAnalysis).where(
            AIAnalysis.analysis_run_id == run.id,
            AIAnalysis.subject_type == subject_type,
            AIAnalysis.subject_key == subject_key,
        )
    )


def read_stored(
    db: Session, run: AnalysisRun, subject_type: AISubjectType, subject_key: str
) -> AIAnalysisRead | None:
    stored = _find_stored(db, run, subject_type, subject_key)
    return to_read(stored, True) if stored is not None else None


def _input_hash(payload: dict, model: str) -> str:
    material = json.dumps(
        {"version": PROMPT_VERSION, "model": model, "payload": payload},
        sort_keys=True,
        ensure_ascii=False,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _generate[T: BaseModel](
    db: Session,
    run: AnalysisRun,
    subject_type: AISubjectType,
    subject_key: str,
    payload: dict,
    schema: type[T],
    analyst: Analyst,
    refresh: bool,
    validate: Callable[[T], None] | None = None,
) -> AIAnalysisRead:
    safe_payload = fit_to_budget(sanitize_payload(payload), get_settings().ai_max_prompt_chars)
    input_hash = _input_hash(safe_payload, analyst.model_name)
    existing = _find_stored(db, run, subject_type, subject_key)
    if existing is not None and existing.input_hash == input_hash and not refresh:
        return to_read(existing, True)
    output = analyst.generate(SYSTEM_INSTRUCTION, safe_payload, schema)
    if validate is not None:
        validate(output)
    now = datetime.now(timezone.utc)
    if existing is None:
        existing = AIAnalysis(
            analysis_run_id=run.id, subject_type=subject_type, subject_key=subject_key
        )
        db.add(existing)
    existing.model = analyst.model_name
    existing.input_hash = input_hash
    existing.content = output.model_dump()
    existing.generated_at = now
    db.commit()
    db.refresh(existing)
    return to_read(existing, False)


def analyze_finding(
    db: Session, run: AnalysisRun, finding: FindingDetail, analyst: Analyst, refresh: bool
) -> AIAnalysisRead:
    return _generate(
        db,
        run,
        AISubjectType.FINDING,
        str(finding.id),
        finding_payload(finding),
        FindingAnalysisOutput,
        analyst,
        refresh,
    )


def _require_every_step(step_count: int) -> Callable[[AttackPathAnalysisOutput], None]:
    def validate(output: AttackPathAnalysisOutput) -> None:
        numbers = sorted(item.step for item in output.steps)
        if numbers != list(range(1, step_count + 1)):
            raise AIInvalidResponseError(
                "The AI response did not explain each path step exactly once."
            )

    return validate


def analyze_attack_path(
    db: Session, run: AnalysisRun, path: AttackPathDetail, analyst: Analyst, refresh: bool
) -> AIAnalysisRead:
    return _generate(
        db,
        run,
        AISubjectType.ATTACK_PATH,
        str(path.id),
        attack_path_payload(path),
        AttackPathAnalysisOutput,
        analyst,
        refresh,
        _require_every_step(len(path.edges)),
    )


def analyze_summary(
    db: Session, run: AnalysisRun, analyst: Analyst, refresh: bool
) -> AIAnalysisRead:
    detail = run_detail(db, run)
    findings = list_findings(db, run, FindingFilters(limit=SUMMARY_FINDINGS))
    paths = list_attack_paths(db, run, AttackPathFilters(limit=SUMMARY_PATHS))
    return _generate(
        db,
        run,
        AISubjectType.SUMMARY,
        RUN_KEY,
        summary_payload(detail, findings, paths),
        SecuritySummaryOutput,
        analyst,
        refresh,
    )