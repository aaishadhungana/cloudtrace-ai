from collections import defaultdict
from typing import Any

from app.engine.catalog import WRITE_TYPES
from app.engine.evaluation import EffectiveRelationship
from app.engine.evidence import limited, relationship_evidence
from app.engine.models import EFFECT_ALLOW, TARGET_RESOURCE, Snapshot
from app.models.enums import RelationshipType


class AnalysisContext:
    def __init__(self, snapshot: Snapshot, relationships: list[EffectiveRelationship]) -> None:
        self.snapshot = snapshot
        self.relationships = tuple(relationships)
        grouped: dict[str, list[EffectiveRelationship]] = defaultdict(list)
        for relationship in self.relationships:
            grouped[relationship.source_arn].append(relationship)
        self._by_source = dict(grouped)

    def from_source(self, arn: str) -> list[EffectiveRelationship]:
        return self._by_source.get(arn, [])

    def sensitive_reach(self, arn: str) -> list[EffectiveRelationship]:
        return [
            item
            for item in self.from_source(arn)
            if item.effect == EFFECT_ALLOW
            and item.target_kind == TARGET_RESOURCE
            and self.snapshot.resource_index[item.target_arn].is_sensitive
        ]

    def reaches_sensitive(self, arn: str) -> bool:
        return bool(self.sensitive_reach(arn))

    def can_write(self, arn: str) -> bool:
        return any(
            item.effect == EFFECT_ALLOW and item.relationship_type in WRITE_TYPES
            for item in self.from_source(arn)
        )

    def can_assume(self, source_arn: str, target_arn: str) -> bool:
        return any(
            item.effect == EFFECT_ALLOW
            and item.relationship_type is RelationshipType.CAN_ASSUME
            and item.target_arn == target_arn
            for item in self.from_source(source_arn)
        )

    def sensitive_access_evidence(self, arn: str) -> list[dict[str, Any]]:
        return limited([relationship_evidence(item) for item in self.sensitive_reach(arn)])