from typing import Any

from app.engine.evaluation import EffectiveRelationship
from app.engine.models import Snapshot, Statement, StatementRef

EVIDENCE_LIMIT = 25


def ref_summary(ref: StatementRef) -> dict[str, Any]:
    return {"kind": f"{ref.kind}_statement", "owner": ref.owner, "statement_index": ref.index}


def statement_evidence(snapshot: Snapshot, ref: StatementRef) -> dict[str, Any]:
    statement = snapshot.statement(ref)
    evidence: dict[str, Any] = {
        **ref_summary(ref),
        "sid": statement.sid,
        "effect": statement.effect,
        "actions": list(statement.actions),
        "conditions": statement.conditions,
    }
    if isinstance(statement, Statement):
        evidence["resources"] = list(statement.resources)
        evidence["policy_name"] = snapshot.policies[ref.owner].name
    else:
        evidence["principals"] = list(statement.principals)
    return evidence


def relationship_evidence(relationship: EffectiveRelationship) -> dict[str, Any]:
    return {
        "kind": "effective_access",
        "source": relationship.source_arn,
        "target": relationship.target_arn,
        "relationship": relationship.relationship_type.value,
        "effect": relationship.effect,
        "decision": relationship.decision.value,
        "actions": list(relationship.actions),
        "granted_by": [ref_summary(ref) for ref in relationship.allow_refs],
        "denied_by": [ref_summary(ref) for ref in relationship.deny_refs],
        "notes": list(relationship.notes),
    }


def limited(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if len(items) <= EVIDENCE_LIMIT:
        return items
    return [*items[:EVIDENCE_LIMIT], {"kind": "truncated", "omitted": len(items) - EVIDENCE_LIMIT}]