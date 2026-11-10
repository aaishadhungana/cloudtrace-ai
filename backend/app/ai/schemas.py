from typing import Any

from pydantic import BaseModel

from app.ai.errors import AIInvalidResponseError

MAX_TEXT_CHARS = 1200
MAX_LIST_ITEMS = 8


class RemediationStep(BaseModel):
    action: str
    rationale: str
    verify_before_applying: str


class FindingAnalysisOutput(BaseModel):
    what_was_detected: str
    why_it_is_risky: str
    potential_impact: str
    evidence_established: list[str]
    remaining_uncertainty: list[str]
    remediation: list[RemediationStep]


class StepExplanation(BaseModel):
    step: int
    explanation: str


class AttackPathAnalysisOutput(BaseModel):
    overview: str
    steps: list[StepExplanation]
    potential_impact: str
    why_it_deserves_attention: str
    verify_before_claiming_exploitability: list[str]
    remediation: list[RemediationStep]


class PriorityItem(BaseModel):
    title: str
    why: str
    recommended_action: str


class SecuritySummaryOutput(BaseModel):
    overview: str
    priorities: list[PriorityItem]
    caveats: list[str]


def _check(value: Any) -> None:
    if isinstance(value, str):
        if not value.strip():
            raise AIInvalidResponseError("The AI response contained an empty text field")
        if len(value) > MAX_TEXT_CHARS:
            raise AIInvalidResponseError("The AI response contained an oversized text field")
    elif isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise AIInvalidResponseError("The AI response contained an oversized list")
        for item in value:
            _check(item)
    elif isinstance(value, dict):
        for item in value.values():
            _check(item)


def check_limits(output: BaseModel) -> None:
    _check(output.model_dump())