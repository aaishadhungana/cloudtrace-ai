from dataclasses import dataclass, field

from app.engine.catalog import IDENTITY_CATALOG, RESOURCE_CATALOG, ActionSpec
from app.engine.matching import matches_action, matches_resource
from app.engine.models import (
    EFFECT_ALLOW,
    EFFECT_DENY,
    POLICY_KIND,
    PUBLIC_PRINCIPAL,
    RESOURCE_POLICY_KIND,
    TARGET_IDENTITY,
    TARGET_RESOURCE,
    TRUST_KIND,
    Decision,
    IdentityNode,
    ResourceNode,
    Snapshot,
    StatementRef,
)
from app.models.enums import RelationshipType

ASSUME_ACTION = "sts:AssumeRole"

EXTERNAL_NOTE = "Permissions in the external account are not modeled, so the result is conditional."
CONDITION_NOTE = "A statement has conditions that cannot be evaluated without request context."
CONDITIONAL_DENY_NOTE = "A conditional Deny applies and cannot be evaluated without request context."
NO_TRUST_NOTE = "The role has no trust policy in the import, so assumption cannot be established."

DECISION_RANK = {
    Decision.ALLOWED: 3,
    Decision.CONDITIONAL: 2,
    Decision.EXPLICITLY_DENIED: 1,
    Decision.NOT_ALLOWED: 0,
}


@dataclass(frozen=True)
class Evaluation:
    decision: Decision
    allow_refs: tuple[StatementRef, ...] = ()
    deny_refs: tuple[StatementRef, ...] = ()
    supporting_refs: tuple[StatementRef, ...] = ()
    actions: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class EffectiveRelationship:
    source_arn: str
    target_arn: str
    target_kind: str
    relationship_type: RelationshipType
    effect: str
    decision: Decision
    allow_refs: tuple[StatementRef, ...]
    deny_refs: tuple[StatementRef, ...]
    supporting_refs: tuple[StatementRef, ...]
    actions: tuple[str, ...]
    notes: tuple[str, ...]


@dataclass
class _Tally:
    allow_unconditional: list[StatementRef] = field(default_factory=list)
    allow_conditional: list[StatementRef] = field(default_factory=list)
    deny_unconditional: list[StatementRef] = field(default_factory=list)
    deny_conditional: list[StatementRef] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def add(self, effect: str, conditional: bool, ref: StatementRef) -> None:
        if effect == EFFECT_ALLOW:
            target = self.allow_conditional if conditional else self.allow_unconditional
        else:
            target = self.deny_conditional if conditional else self.deny_unconditional
        target.append(ref)

    def demote_allows(self, note: str) -> None:
        if self.allow_unconditional:
            self.allow_conditional = self.allow_unconditional + self.allow_conditional
            self.allow_unconditional = []
            self.notes.append(note)

    def decision(self) -> Decision:
        if not self.allow_unconditional and not self.allow_conditional:
            return Decision.NOT_ALLOWED
        if self.deny_unconditional:
            return Decision.EXPLICITLY_DENIED
        if self.deny_conditional:
            return Decision.CONDITIONAL
        return Decision.ALLOWED if self.allow_unconditional else Decision.CONDITIONAL


def _unique[T](items: list[T] | tuple[T, ...]) -> tuple[T, ...]:
    return tuple(dict.fromkeys(items))


def _finish(
    tally: _Tally, actions: tuple[str, ...], supporting: tuple[StatementRef, ...] = ()
) -> Evaluation:
    decision = tally.decision()
    if decision is Decision.NOT_ALLOWED:
        return Evaluation(decision=decision)
    notes = list(tally.notes)
    if tally.deny_conditional and not tally.deny_unconditional:
        notes.append(CONDITIONAL_DENY_NOTE)
    if decision is Decision.CONDITIONAL and tally.allow_conditional and not tally.deny_conditional:
        notes.append(CONDITION_NOTE)
    return Evaluation(
        decision=decision,
        allow_refs=_unique(tally.allow_unconditional + tally.allow_conditional),
        deny_refs=_unique(tally.deny_unconditional + tally.deny_conditional),
        supporting_refs=_unique(supporting),
        actions=actions,
        notes=_unique(notes),
    )


def _tally_identity_policies(
    snapshot: Snapshot, identity: IdentityNode, action: str, target_arn: str
) -> _Tally:
    tally = _Tally()
    for policy_id in identity.policy_ids:
        for index, statement in enumerate(snapshot.policies[policy_id].statements):
            if not any(matches_action(pattern, action) for pattern in statement.actions):
                continue
            if not any(matches_resource(pattern, target_arn) for pattern in statement.resources):
                continue
            tally.add(
                statement.effect,
                statement.has_conditions,
                StatementRef(POLICY_KIND, policy_id, index),
            )
    return tally


def _add_resource_policy(
    tally: _Tally,
    snapshot: Snapshot,
    resource: ResourceNode,
    identity: IdentityNode,
    action: str,
) -> None:
    policy = resource.resource_policy
    if policy is None:
        return
    external = snapshot.is_external(identity)
    for index, statement in enumerate(policy.statements):
        public = PUBLIC_PRINCIPAL in statement.principals
        if not public and identity.arn not in statement.principals:
            continue
        if not any(matches_action(pattern, action) for pattern in statement.actions):
            continue
        ref = StatementRef(RESOURCE_POLICY_KIND, resource.arn, index)
        if (
            statement.effect == EFFECT_ALLOW
            and external
            and not public
            and not statement.has_conditions
        ):
            tally.allow_conditional.append(ref)
            tally.notes.append(EXTERNAL_NOTE)
        else:
            tally.add(statement.effect, statement.has_conditions, ref)


def evaluate_access(
    snapshot: Snapshot, identity: IdentityNode, resource: ResourceNode, spec: ActionSpec
) -> Evaluation:
    target = resource.arn + spec.target_suffix
    tally = _tally_identity_policies(snapshot, identity, spec.action, target)
    _add_resource_policy(tally, snapshot, resource, identity, spec.action)
    return _finish(tally, (spec.action,))


def evaluate_identity_action(
    snapshot: Snapshot, identity: IdentityNode, action: str, target_arn: str
) -> Evaluation:
    tally = _tally_identity_policies(snapshot, identity, action, target_arn)
    return _finish(tally, (action,))


def evaluate_assume(snapshot: Snapshot, identity: IdentityNode, role: IdentityNode) -> Evaluation:
    trust = role.trust_policy
    if trust is None:
        return Evaluation(decision=Decision.NOT_ALLOWED, notes=(NO_TRUST_NOTE,))
    tally = _Tally()
    for index, statement in enumerate(trust.statements):
        if PUBLIC_PRINCIPAL not in statement.principals and identity.arn not in statement.principals:
            continue
        if not any(matches_action(pattern, ASSUME_ACTION) for pattern in statement.actions):
            continue
        tally.add(
            statement.effect,
            statement.has_conditions,
            StatementRef(TRUST_KIND, role.arn, index),
        )
    identity_side = _tally_identity_policies(snapshot, identity, ASSUME_ACTION, role.arn)
    tally.deny_unconditional.extend(identity_side.deny_unconditional)
    tally.deny_conditional.extend(identity_side.deny_conditional)
    if snapshot.is_external(identity):
        tally.demote_allows(EXTERNAL_NOTE)
    supporting = tuple(identity_side.allow_unconditional + identity_side.allow_conditional)
    return _finish(tally, (ASSUME_ACTION,), supporting)


def _merge(evaluations: list[Evaluation]) -> Evaluation:
    best = max(DECISION_RANK[item.decision] for item in evaluations)
    chosen = [item for item in evaluations if DECISION_RANK[item.decision] == best]
    return Evaluation(
        decision=chosen[0].decision,
        allow_refs=_unique([ref for item in chosen for ref in item.allow_refs]),
        deny_refs=_unique([ref for item in chosen for ref in item.deny_refs]),
        supporting_refs=_unique([ref for item in chosen for ref in item.supporting_refs]),
        actions=_unique([action for item in chosen for action in item.actions]),
        notes=_unique([note for item in chosen for note in item.notes]),
    )


def _record(
    relationships: list[EffectiveRelationship],
    source_arn: str,
    target_arn: str,
    target_kind: str,
    relationship_type: RelationshipType,
    evaluation: Evaluation,
) -> None:
    if evaluation.decision in (Decision.ALLOWED, Decision.CONDITIONAL):
        effect = EFFECT_ALLOW
    elif evaluation.decision is Decision.EXPLICITLY_DENIED:
        effect = EFFECT_DENY
    else:
        return
    relationships.append(
        EffectiveRelationship(
            source_arn=source_arn,
            target_arn=target_arn,
            target_kind=target_kind,
            relationship_type=relationship_type,
            effect=effect,
            decision=evaluation.decision,
            allow_refs=evaluation.allow_refs,
            deny_refs=evaluation.deny_refs,
            supporting_refs=evaluation.supporting_refs,
            actions=evaluation.actions,
            notes=evaluation.notes,
        )
    )


def compute_relationships(snapshot: Snapshot) -> list[EffectiveRelationship]:
    relationships: list[EffectiveRelationship] = []
    for identity in snapshot.identities:
        for resource in snapshot.resources:
            if not identity.policy_ids and resource.resource_policy is None:
                continue
            catalog = RESOURCE_CATALOG.get(resource.resource_type, {})
            for relationship_type, specs in catalog.items():
                evaluation = _merge(
                    [evaluate_access(snapshot, identity, resource, spec) for spec in specs]
                )
                _record(
                    relationships,
                    identity.arn,
                    resource.arn,
                    TARGET_RESOURCE,
                    relationship_type,
                    evaluation,
                )
        for target in snapshot.identities:
            catalog = IDENTITY_CATALOG.get(target.identity_type, {})
            for relationship_type, specs in catalog.items():
                is_self = target.arn == identity.arn
                if is_self and relationship_type is not RelationshipType.CAN_MODIFY_POLICY:
                    continue
                if relationship_type is RelationshipType.CAN_ASSUME:
                    evaluation = evaluate_assume(snapshot, identity, target)
                elif identity.policy_ids:
                    evaluation = _merge(
                        [
                            evaluate_identity_action(
                                snapshot, identity, spec.action, target.arn + spec.target_suffix
                            )
                            for spec in specs
                        ]
                    )
                else:
                    continue
                _record(
                    relationships,
                    identity.arn,
                    target.arn,
                    TARGET_IDENTITY,
                    relationship_type,
                    evaluation,
                )
    relationships.sort(
        key=lambda item: (item.source_arn, item.target_arn, item.relationship_type.value)
    )
    return relationships