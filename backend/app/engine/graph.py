from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

import networkx as nx

from app.engine.evaluation import DECISION_RANK, EffectiveRelationship
from app.engine.models import EFFECT_ALLOW, TARGET_IDENTITY, TARGET_RESOURCE, Snapshot
from app.models.enums import Decision, RelationshipType

PIVOT_TYPES = frozenset({RelationshipType.CAN_ASSUME, RelationshipType.CAN_PASS_ROLE})
KIND = "kind"
RELATIONSHIPS = "relationships"


@dataclass(frozen=True)
class PathLimits:
    max_length: int = 5
    max_paths_per_pair: int = 3
    max_paths: int = 200
    max_candidates_per_pair: int = 500


def _pivot_rank(relationship: EffectiveRelationship) -> tuple[int, int]:
    type_rank = 0 if relationship.relationship_type is RelationshipType.CAN_ASSUME else 1
    return (type_rank, -DECISION_RANK[relationship.decision])


def build_graph(
    snapshot: Snapshot, relationships: Iterable[EffectiveRelationship]
) -> nx.DiGraph:
    graph = nx.DiGraph()
    for identity in snapshot.identities:
        graph.add_node(identity.arn, **{KIND: TARGET_IDENTITY})
    for resource in snapshot.resources:
        graph.add_node(resource.arn, **{KIND: TARGET_RESOURCE})
    grouped: dict[tuple[str, str], list[EffectiveRelationship]] = defaultdict(list)
    for relationship in relationships:
        if relationship.effect != EFFECT_ALLOW:
            continue
        if (
            relationship.target_kind == TARGET_IDENTITY
            and relationship.relationship_type not in PIVOT_TYPES
        ):
            continue
        grouped[(relationship.source_arn, relationship.target_arn)].append(relationship)
    for (source, target), items in grouped.items():
        if graph.nodes[target][KIND] == TARGET_IDENTITY:
            items = [min(items, key=_pivot_rank)]
        graph.add_edge(source, target, **{RELATIONSHIPS: tuple(items)})
    return graph


def edge_relationships(
    graph: nx.DiGraph, source: str, target: str
) -> tuple[EffectiveRelationship, ...]:
    return graph[source][target][RELATIONSHIPS]


def has_unconditional_edge(graph: nx.DiGraph, source: str, target: str) -> bool:
    if not graph.has_edge(source, target):
        return False
    return any(
        item.decision is Decision.ALLOWED for item in edge_relationships(graph, source, target)
    )


def reachable_resources(graph: nx.DiGraph, arn: str, max_depth: int | None = None) -> list[str]:
    distances = nx.single_source_shortest_path_length(graph, arn, cutoff=max_depth)
    return sorted(
        node for node in distances if node != arn and graph.nodes[node][KIND] == TARGET_RESOURCE
    )


def identities_reaching(
    graph: nx.DiGraph, resource_arn: str, max_depth: int | None = None
) -> list[str]:
    distances = nx.single_source_shortest_path_length(
        graph.reverse(copy=False), resource_arn, cutoff=max_depth
    )
    return sorted(
        node
        for node in distances
        if node != resource_arn and graph.nodes[node][KIND] == TARGET_IDENTITY
    )


def assumable_roles(graph: nx.DiGraph, arn: str) -> list[str]:
    return sorted(
        target
        for target in graph.successors(arn)
        if any(
            item.relationship_type is RelationshipType.CAN_ASSUME
            for item in edge_relationships(graph, arn, target)
        )
    )