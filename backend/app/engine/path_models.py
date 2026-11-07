from dataclasses import dataclass
from typing import Any

from app.engine.evaluation import EffectiveRelationship
from app.engine.scoring import RiskAssessment
from app.models.enums import Decision, PathClassification, RelationshipType


@dataclass(frozen=True)
class PathStep:
    source_arn: str
    target_arn: str
    relationships: tuple[EffectiveRelationship, ...]

    @property
    def decision(self) -> Decision:
        return self.relationships[0].decision

    @property
    def relationship_types(self) -> tuple[RelationshipType, ...]:
        return tuple(item.relationship_type for item in self.relationships)


@dataclass(frozen=True)
class AttackPathDraft:
    fingerprint: str
    start_arn: str
    target_arn: str
    steps: tuple[PathStep, ...]
    classification: PathClassification
    assessment: RiskAssessment
    nodes: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    summary: str