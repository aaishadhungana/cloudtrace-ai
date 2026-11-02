from collections.abc import Iterable, Iterator

from app.engine.matching import is_broad_resource, matches_resource
from app.engine.models import (
    EFFECT_ALLOW,
    POLICY_KIND,
    IdentityNode,
    Snapshot,
    Statement,
    StatementRef,
)

CONDITION_NOTE = (
    " The statement has conditions the engine cannot evaluate without request context, "
    "so the real grant may be narrower."
)


def policy_statements(
    snapshot: Snapshot, identity: IdentityNode
) -> Iterator[tuple[StatementRef, Statement]]:
    for policy_id in identity.policy_ids:
        for index, statement in enumerate(snapshot.policies[policy_id].statements):
            yield StatementRef(POLICY_KIND, policy_id, index), statement


def has_broad_resource(snapshot: Snapshot, statement: Statement) -> bool:
    return any(is_broad_resource(pattern, snapshot.target_arns) for pattern in statement.resources)


def is_admin_statement(snapshot: Snapshot, statement: Statement) -> bool:
    return (
        statement.effect == EFFECT_ALLOW
        and "*" in statement.actions
        and has_broad_resource(snapshot, statement)
    )


def is_wildcard_statement(snapshot: Snapshot, statement: Statement) -> bool:
    if statement.effect != EFFECT_ALLOW or not has_broad_resource(snapshot, statement):
        return False
    return "*" in statement.actions or any(action.endswith(":*") for action in statement.actions)


def has_admin_statement(snapshot: Snapshot, identity: IdentityNode) -> bool:
    return any(
        is_admin_statement(snapshot, statement)
        for _, statement in policy_statements(snapshot, identity)
    )


def grants_through_broad_pattern(snapshot: Snapshot, statement: Statement, target_arn: str) -> bool:
    return any(
        is_broad_resource(pattern, snapshot.target_arns)
        and (matches_resource(pattern, target_arn) or matches_resource(pattern, f"{target_arn}/*"))
        for pattern in statement.resources
    )


def unique_refs(refs: Iterable[StatementRef]) -> list[StatementRef]:
    return list(dict.fromkeys(refs))