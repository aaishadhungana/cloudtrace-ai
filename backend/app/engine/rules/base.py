from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.engine.context import AnalysisContext
from app.engine.scoring import RiskAssessment


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    title: str
    description: str
    finding_type: str


@dataclass(frozen=True)
class FindingDraft:
    rule_id: str
    finding_type: str
    title: str
    fingerprint: str
    identity_arn: str | None
    resource_arn: str | None
    assessment: RiskAssessment
    evidence: list[dict[str, Any]]
    explanation: str
    remediation: str


@dataclass(frozen=True)
class Rule:
    info: RuleInfo
    detect: Callable[[AnalysisContext], list[FindingDraft]]