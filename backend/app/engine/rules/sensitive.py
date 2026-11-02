from app.engine.catalog import WRITE_TYPES
from app.engine.context import AnalysisContext
from app.engine.evaluation import EffectiveRelationship
from app.engine.evidence import limited, relationship_evidence, statement_evidence
from app.engine.fingerprint import make_fingerprint
from app.engine.models import (
    EFFECT_ALLOW,
    EFFECT_DENY,
    POLICY_KIND,
    TARGET_RESOURCE,
    Decision,
)
from app.engine.rules.base import FindingDraft, RuleInfo
from app.engine.rules.shared import (
    grants_through_broad_pattern,
    is_wildcard_statement,
    unique_refs,
)
from app.engine.scoring import Capability, assess

BROAD_SENSITIVE_INFO = RuleInfo(
    rule_id="CT-IAM-003",
    title="Sensitive resource reachable through a broad resource pattern",
    description=(
        "An identity reaches a resource marked sensitive through allow statements whose resource "
        "patterns also match other resources."
    ),
    finding_type="broad_sensitive_access",
)

DENY_DEPENDENCY_INFO = RuleInfo(
    rule_id="CT-IAM-010",
    title="Sensitive resource protected only by an explicit Deny",
    description=(
        "Broad allow statements would grant access to a sensitive resource, and only an explicit "
        "Deny statement prevents it."
    ),
    finding_type="deny_dependency",
)


def _group(
    context: AnalysisContext, relationships: list[EffectiveRelationship]
) -> dict[tuple[str, str], list[EffectiveRelationship]]:
    grouped: dict[tuple[str, str], list[EffectiveRelationship]] = {}
    for relationship in relationships:
        grouped.setdefault((relationship.source_arn, relationship.target_arn), []).append(
            relationship
        )
    return grouped


def _is_broad_candidate(context: AnalysisContext, relationship: EffectiveRelationship) -> bool:
    snapshot = context.snapshot
    if relationship.effect != EFFECT_ALLOW or relationship.target_kind != TARGET_RESOURCE:
        return False
    resource = snapshot.resource_index[relationship.target_arn]
    identity = snapshot.identity_index[relationship.source_arn]
    if not resource.is_sensitive or snapshot.is_external(identity):
        return False
    refs = [ref for ref in relationship.allow_refs if ref.kind == POLICY_KIND]
    if not refs:
        return False
    statements = [snapshot.policy_statement(ref) for ref in refs]
    if any(is_wildcard_statement(snapshot, statement) for statement in statements):
        return False
    return any(
        grants_through_broad_pattern(snapshot, statement, resource.arn) for statement in statements
    )


def detect_broad_sensitive_access(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    candidates = [item for item in context.relationships if _is_broad_candidate(context, item)]
    drafts: list[FindingDraft] = []
    for (source_arn, target_arn), relationships in _group(context, candidates).items():
        identity = snapshot.identity_index[source_arn]
        resource = snapshot.resource_index[target_arn]
        kinds = ", ".join(sorted({item.relationship_type.value for item in relationships}))
        assessment = assess(
            Capability.SENSITIVE_BROAD_GRANT,
            reaches_sensitive=True,
            can_write=any(item.relationship_type in WRITE_TYPES for item in relationships),
            conditional=all(item.decision is Decision.CONDITIONAL for item in relationships),
        )
        refs = unique_refs(ref for item in relationships for ref in item.allow_refs)
        drafts.append(
            FindingDraft(
                rule_id=BROAD_SENSITIVE_INFO.rule_id,
                finding_type=BROAD_SENSITIVE_INFO.finding_type,
                title=f"{identity.name} reaches sensitive resource {resource.name} by pattern",
                fingerprint=make_fingerprint(BROAD_SENSITIVE_INFO.rule_id, source_arn, target_arn),
                identity_arn=source_arn,
                resource_arn=target_arn,
                assessment=assessment,
                evidence=limited(
                    [relationship_evidence(item) for item in relationships]
                    + [statement_evidence(snapshot, ref) for ref in refs]
                ),
                explanation=(
                    f"{identity.name} reaches the sensitive resource {resource.name} ({kinds}) "
                    "through allow statements whose resource patterns also match other resources. "
                    "Access to customer data or secrets is granted by pattern instead of by "
                    "explicit resource."
                ),
                remediation=(
                    f"Scope the grant to the exact ARNs of the resources {identity.name} needs. If "
                    f"{resource.name} is not required, change the resource patterns so they no "
                    "longer match it, and confirm the remaining access still works before applying."
                ),
            )
        )
    return drafts


def detect_deny_dependency(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    candidates = []
    for relationship in context.relationships:
        if relationship.effect != EFFECT_DENY or relationship.target_kind != TARGET_RESOURCE:
            continue
        resource = snapshot.resource_index[relationship.target_arn]
        identity = snapshot.identity_index[relationship.source_arn]
        if resource.is_sensitive and not snapshot.is_external(identity) and relationship.allow_refs:
            candidates.append(relationship)
    drafts: list[FindingDraft] = []
    for (source_arn, target_arn), relationships in _group(context, candidates).items():
        identity = snapshot.identity_index[source_arn]
        resource = snapshot.resource_index[target_arn]
        allow_refs = unique_refs(ref for item in relationships for ref in item.allow_refs)
        deny_refs = unique_refs(ref for item in relationships for ref in item.deny_refs)
        drafts.append(
            FindingDraft(
                rule_id=DENY_DEPENDENCY_INFO.rule_id,
                finding_type=DENY_DEPENDENCY_INFO.finding_type,
                title=f"Access to {resource.name} for {identity.name} depends on an explicit Deny",
                fingerprint=make_fingerprint(DENY_DEPENDENCY_INFO.rule_id, source_arn, target_arn),
                identity_arn=source_arn,
                resource_arn=target_arn,
                assessment=assess(Capability.DENY_DEPENDENCY, reaches_sensitive=True),
                evidence=limited(
                    [relationship_evidence(item) for item in relationships]
                    + [statement_evidence(snapshot, ref) for ref in [*allow_refs, *deny_refs]]
                ),
                explanation=(
                    f"{identity.name} is allowed to access {resource.name} by broad allow "
                    "statements, and only explicit Deny statements prevent it. If a Deny statement "
                    "is removed or edited, access opens up."
                ),
                remediation=(
                    f"Narrow the allow statements so they no longer match {resource.name}, instead "
                    "of relying on a Deny statement to block it."
                ),
            )
        )
    return drafts