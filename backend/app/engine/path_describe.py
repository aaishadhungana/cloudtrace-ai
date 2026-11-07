from typing import Any

from app.engine.evidence import relationship_evidence, statement_evidence
from app.engine.models import Snapshot
from app.engine.path_models import PathStep
from app.engine.rules.shared import unique_refs
from app.models.enums import Decision, RelationshipType

PASS_ROLE_ASSUMPTION = (
    "Assumes the identity can start a service that runs with this role. "
    "That capability is not evaluated."
)

TERMINAL_ORDER = (
    RelationshipType.CAN_READ,
    RelationshipType.CAN_WRITE,
    RelationshipType.CAN_MODIFY_POLICY,
)

TERMINAL_VERBS = {
    RelationshipType.CAN_READ: "read",
    RelationshipType.CAN_WRITE: "write to",
    RelationshipType.CAN_MODIFY_POLICY: "change the access policy of",
}


def _name(snapshot: Snapshot, arn: str) -> str:
    identity = snapshot.identity_index.get(arn)
    if identity is not None:
        return identity.name
    return snapshot.resource_index[arn].name


def _join(parts: list[str]) -> str:
    if len(parts) <= 1:
        return "".join(parts)
    return ", ".join(parts[:-1]) + " and " + parts[-1]


def build_summary(snapshot: Snapshot, steps: tuple[PathStep, ...]) -> str:
    sentences = []
    last_index = len(steps) - 1
    for index, step in enumerate(steps):
        source = _name(snapshot, step.source_arn)
        target = _name(snapshot, step.target_arn)
        types = step.relationship_types
        if index == last_index:
            verbs = [TERMINAL_VERBS[item] for item in TERMINAL_ORDER if item in types]
            sentences.append(f"{source} can {_join(verbs)} {target}")
        elif RelationshipType.CAN_ASSUME in types:
            sentences.append(f"{source} can assume {target}")
        else:
            sentences.append(f"{source} can pass {target} to a service")
    return ". ".join(sentences) + "."


def _node(snapshot: Snapshot, arn: str, position: str) -> dict[str, Any]:
    identity = snapshot.identity_index.get(arn)
    if identity is not None:
        return {
            "arn": arn,
            "name": identity.name,
            "kind": "identity",
            "type": identity.identity_type.value,
            "is_external": snapshot.is_external(identity),
            "is_sensitive": False,
            "position": position,
        }
    resource = snapshot.resource_index[arn]
    return {
        "arn": arn,
        "name": resource.name,
        "kind": "resource",
        "type": resource.resource_type.value,
        "is_external": False,
        "is_sensitive": resource.is_sensitive,
        "position": position,
    }


def build_nodes(snapshot: Snapshot, steps: tuple[PathStep, ...]) -> list[dict[str, Any]]:
    arns = [steps[0].source_arn, *[step.target_arn for step in steps]]
    last_index = len(arns) - 1
    nodes = []
    for index, arn in enumerate(arns):
        position = "start" if index == 0 else "target" if index == last_index else "pivot"
        nodes.append(_node(snapshot, arn, position))
    return nodes


def _edge(step: PathStep) -> dict[str, Any]:
    notes = list(dict.fromkeys(note for item in step.relationships for note in item.notes))
    assumption_parts = []
    if RelationshipType.CAN_PASS_ROLE in step.relationship_types:
        assumption_parts.append(PASS_ROLE_ASSUMPTION)
    if step.decision is Decision.CONDITIONAL:
        assumption_parts.extend(notes)
    return {
        "source": step.source_arn,
        "target": step.target_arn,
        "relationship": step.relationships[0].relationship_type.value,
        "relationships": [item.value for item in step.relationship_types],
        "decision": step.decision.value,
        "actions": list(
            dict.fromkeys(action for item in step.relationships for action in item.actions)
        ),
        "notes": notes,
        "assumption": " ".join(assumption_parts) or None,
    }


def build_edges(steps: tuple[PathStep, ...]) -> list[dict[str, Any]]:
    return [_edge(step) for step in steps]


def build_evidence(snapshot: Snapshot, steps: tuple[PathStep, ...]) -> list[dict[str, Any]]:
    evidence = []
    for index, step in enumerate(steps):
        refs = unique_refs(
            ref
            for item in step.relationships
            for ref in (*item.allow_refs, *item.supporting_refs)
        )
        evidence.append(
            {
                "kind": "path_step",
                "step": index,
                "source": step.source_arn,
                "target": step.target_arn,
                "relationships": [relationship_evidence(item) for item in step.relationships],
                "statements": [statement_evidence(snapshot, ref) for ref in refs],
            }
        )
    return evidence