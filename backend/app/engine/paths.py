from dataclasses import dataclass
from itertools import islice

import networkx as nx

from app.engine.catalog import WRITE_TYPES
from app.engine.evaluation import DECISION_RANK, EffectiveRelationship
from app.engine.fingerprint import make_fingerprint
from app.engine.graph import PathLimits, edge_relationships, has_unconditional_edge
from app.engine.models import (
    POLICY_KIND,
    PUBLIC_PRINCIPAL,
    TRUST_KIND,
    PrincipalStatement,
    Snapshot,
)
from app.engine.path_describe import build_edges, build_evidence, build_nodes, build_summary
from app.engine.path_models import AttackPathDraft, PathStep
from app.engine.path_scoring import assess_path
from app.engine.rules.shared import grants_through_broad_pattern, is_wildcard_statement
from app.models.enums import Decision, PathClassification, RelationshipType

ACCESS_PRIORITY = {
    RelationshipType.CAN_WRITE: 0,
    RelationshipType.CAN_MODIFY_POLICY: 1,
    RelationshipType.CAN_READ: 2,
}


@dataclass(frozen=True)
class PathDiscovery:
    paths: tuple[AttackPathDraft, ...]
    incomplete: bool


def _terminal_relationships(
    items: tuple[EffectiveRelationship, ...],
) -> tuple[EffectiveRelationship, ...]:
    best = max(DECISION_RANK[item.decision] for item in items)
    kept = [item for item in items if DECISION_RANK[item.decision] == best]
    return tuple(sorted(kept, key=lambda item: ACCESS_PRIORITY.get(item.relationship_type, 9)))


def _build_steps(graph: nx.DiGraph, nodes: list[str]) -> tuple[PathStep, ...]:
    steps = []
    last_index = len(nodes) - 2
    for index in range(len(nodes) - 1):
        source, target = nodes[index], nodes[index + 1]
        relationships = edge_relationships(graph, source, target)
        if index == last_index:
            relationships = _terminal_relationships(relationships)
        steps.append(PathStep(source, target, relationships))
    return tuple(steps)


def _classify(steps: tuple[PathStep, ...]) -> PathClassification:
    for step in steps:
        if step.decision is not Decision.ALLOWED:
            return PathClassification.POTENTIAL
        if RelationshipType.CAN_PASS_ROLE in step.relationship_types:
            return PathClassification.POTENTIAL
    return PathClassification.SUPPORTED


def _broad_terminal(snapshot: Snapshot, step: PathStep) -> bool:
    for relationship in step.relationships:
        for ref in relationship.allow_refs:
            if ref.kind != POLICY_KIND:
                continue
            statement = snapshot.policy_statement(ref)
            if is_wildcard_statement(snapshot, statement) or grants_through_broad_pattern(
                snapshot, statement, step.target_arn
            ):
                return True
    return False


def _public_trust(snapshot: Snapshot, steps: tuple[PathStep, ...]) -> bool:
    for step in steps:
        for relationship in step.relationships:
            if relationship.relationship_type is not RelationshipType.CAN_ASSUME:
                continue
            for ref in relationship.allow_refs:
                if ref.kind != TRUST_KIND:
                    continue
                statement = snapshot.statement(ref)
                if isinstance(statement, PrincipalStatement) and PUBLIC_PRINCIPAL in statement.principals:
                    return True
    return False


def _fingerprint(start: str, target: str, steps: tuple[PathStep, ...]) -> str:
    parts = [
        f"{step.source_arn}>{step.target_arn}:{'+'.join(sorted(item.value for item in step.relationship_types))}"
        for step in steps
    ]
    return make_fingerprint("CT-PATH", start, target, *parts)


def _build_draft(
    snapshot: Snapshot, graph: nx.DiGraph, nodes: list[str]
) -> AttackPathDraft | None:
    if len(nodes) < 3:
        return None
    target = nodes[-1]
    if any(has_unconditional_edge(graph, node, target) for node in nodes[:-2]):
        return None
    steps = _build_steps(graph, nodes)
    start = nodes[0]
    assessment = assess_path(
        length=len(steps),
        broad_terminal=_broad_terminal(snapshot, steps[-1]),
        writes=any(item.relationship_type in WRITE_TYPES for item in steps[-1].relationships),
        external_start=snapshot.is_external(snapshot.identity_index[start]),
        public_trust=_public_trust(snapshot, steps),
        conditional=any(step.decision is Decision.CONDITIONAL for step in steps),
        inferred=any(
            RelationshipType.CAN_PASS_ROLE in step.relationship_types for step in steps
        ),
    )
    return AttackPathDraft(
        fingerprint=_fingerprint(start, target, steps),
        start_arn=start,
        target_arn=target,
        steps=steps,
        classification=_classify(steps),
        assessment=assessment,
        nodes=build_nodes(snapshot, steps),
        edges=build_edges(steps),
        evidence=build_evidence(snapshot, steps),
        summary=build_summary(snapshot, steps),
    )


def _candidates(
    snapshot: Snapshot,
    view: nx.DiGraph,
    graph: nx.DiGraph,
    start: str,
    target: str,
    limits: PathLimits,
) -> tuple[list[AttackPathDraft], bool]:
    iterator = nx.all_simple_edge_paths(view, start, target, cutoff=limits.max_length)
    raw = list(islice(iterator, limits.max_candidates_per_pair + 1))
    hit_limit = len(raw) > limits.max_candidates_per_pair
    drafts: list[AttackPathDraft] = []
    for edge_path in raw[: limits.max_candidates_per_pair]:
        nodes = [edge_path[0][0], *[edge[1] for edge in edge_path]]
        draft = _build_draft(snapshot, graph, nodes)
        if draft is not None:
            drafts.append(draft)
    return drafts, hit_limit


def discover_paths(snapshot: Snapshot, graph: nx.DiGraph, limits: PathLimits) -> PathDiscovery:
    targets = sorted(resource.arn for resource in snapshot.resources if resource.is_sensitive)
    starts = sorted(identity.arn for identity in snapshot.identities)
    selected: list[AttackPathDraft] = []
    incomplete = False
    for target in targets:
        if target not in graph:
            continue
        reachers = nx.ancestors(graph, target)
        view = graph.subgraph(reachers | {target})
        for start in starts:
            if start not in reachers or has_unconditional_edge(graph, start, target):
                continue
            drafts, hit_limit = _candidates(snapshot, view, graph, start, target, limits)
            drafts.sort(key=lambda item: (-item.assessment.score, len(item.steps), item.fingerprint))
            incomplete = incomplete or hit_limit or len(drafts) > limits.max_paths_per_pair
            selected.extend(drafts[: limits.max_paths_per_pair])
    selected.sort(
        key=lambda item: (-item.assessment.score, item.start_arn, item.target_arn, item.fingerprint)
    )
    incomplete = incomplete or len(selected) > limits.max_paths
    return PathDiscovery(paths=tuple(selected[: limits.max_paths]), incomplete=incomplete)