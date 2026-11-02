from app.engine.context import AnalysisContext
from app.engine.evaluation import EffectiveRelationship
from app.engine.evidence import limited, statement_evidence
from app.engine.fingerprint import make_fingerprint
from app.engine.models import EFFECT_ALLOW, POLICY_KIND, TARGET_IDENTITY, Decision
from app.engine.rules.base import FindingDraft, RuleInfo
from app.engine.rules.shared import (
    grants_through_broad_pattern,
    has_admin_statement,
    unique_refs,
)
from app.engine.scoring import Capability, assess
from app.models.enums import RelationshipType

POLICY_MODIFICATION_INFO = RuleInfo(
    rule_id="CT-IAM-006",
    title="Identity can modify IAM policies",
    description="An identity is allowed to change IAM policies, which can be used to grant more access.",
    finding_type="policy_modification",
)

PASS_ROLE_INFO = RuleInfo(
    rule_id="CT-IAM-007",
    title="Identity can pass any role",
    description="An identity is allowed iam:PassRole on a broad resource pattern.",
    finding_type="pass_role_wildcard",
)


def _by_source(
    context: AnalysisContext, relationship_type: RelationshipType
) -> dict[str, list[EffectiveRelationship]]:
    grouped: dict[str, list[EffectiveRelationship]] = {}
    for relationship in context.relationships:
        if (
            relationship.effect == EFFECT_ALLOW
            and relationship.relationship_type is relationship_type
            and relationship.target_kind == TARGET_IDENTITY
        ):
            grouped.setdefault(relationship.source_arn, []).append(relationship)
    return grouped


def detect_policy_modification(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    has_sensitive = any(resource.is_sensitive for resource in snapshot.resources)
    drafts: list[FindingDraft] = []
    for source_arn, relationships in _by_source(context, RelationshipType.CAN_MODIFY_POLICY).items():
        identity = snapshot.identity_index[source_arn]
        if snapshot.is_external(identity) or has_admin_statement(snapshot, identity):
            continue
        controlled = [
            item
            for item in relationships
            if item.target_arn == source_arn or context.can_assume(source_arn, item.target_arn)
        ]
        refs = unique_refs(ref for item in relationships for ref in item.allow_refs)
        actions = sorted({action for item in relationships for action in item.actions})
        assessment = assess(
            Capability.POLICY_MODIFICATION,
            reaches_sensitive=bool(controlled) and has_sensitive,
            can_write=True,
            conditional=all(item.decision is Decision.CONDITIONAL for item in relationships),
        )
        targets = [
            {
                "kind": "policy_modification_target",
                "target": item.target_arn,
                "controlled": item in controlled,
            }
            for item in relationships
        ]
        drafts.append(
            FindingDraft(
                rule_id=POLICY_MODIFICATION_INFO.rule_id,
                finding_type=POLICY_MODIFICATION_INFO.finding_type,
                title=f"{identity.name} can modify IAM policies",
                fingerprint=make_fingerprint(POLICY_MODIFICATION_INFO.rule_id, source_arn),
                identity_arn=source_arn,
                resource_arn=None,
                assessment=assessment,
                evidence=limited(
                    [statement_evidence(snapshot, ref) for ref in refs] + targets
                ),
                explanation=(
                    f"{identity.name} can change IAM policies on {len(relationships)} identities "
                    f"({', '.join(actions)}), including {len(controlled)} it controls directly or "
                    "through role assumption. Policy-modification permissions let an identity grant "
                    "itself or another identity more access."
                ),
                remediation=(
                    f"Remove the IAM policy-modification actions ({', '.join(actions)}) from "
                    f"{identity.name} unless it is a dedicated administrator. Where they are "
                    "required, scope them to specific ARNs and add conditions. Confirm the change "
                    "does not break required automation before applying it."
                ),
            )
        )
    return drafts


def detect_pass_role_wildcard(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    drafts: list[FindingDraft] = []
    for source_arn, relationships in _by_source(context, RelationshipType.CAN_PASS_ROLE).items():
        identity = snapshot.identity_index[source_arn]
        if snapshot.is_external(identity) or has_admin_statement(snapshot, identity):
            continue
        broad = [
            item
            for item in relationships
            if any(
                ref.kind == POLICY_KIND
                and grants_through_broad_pattern(
                    snapshot, snapshot.policy_statement(ref), item.target_arn
                )
                for ref in item.allow_refs
            )
        ]
        if not broad:
            continue
        refs = unique_refs(ref for item in broad for ref in item.allow_refs)
        passable = [
            {
                "kind": "passable_role",
                "role": item.target_arn,
                "reaches_sensitive": context.reaches_sensitive(item.target_arn),
            }
            for item in broad
        ]
        assessment = assess(
            Capability.PASS_ROLE_WILDCARD,
            reaches_sensitive=any(context.reaches_sensitive(item.target_arn) for item in broad),
            role_chain=True,
            conditional=all(item.decision is Decision.CONDITIONAL for item in broad),
        )
        drafts.append(
            FindingDraft(
                rule_id=PASS_ROLE_INFO.rule_id,
                finding_type=PASS_ROLE_INFO.finding_type,
                title=f"{identity.name} can pass any role",
                fingerprint=make_fingerprint(PASS_ROLE_INFO.rule_id, source_arn),
                identity_arn=source_arn,
                resource_arn=None,
                assessment=assessment,
                evidence=limited(
                    [statement_evidence(snapshot, ref) for ref in refs] + passable
                ),
                explanation=(
                    f"{identity.name} is allowed iam:PassRole on a broad pattern covering "
                    f"{len(broad)} roles. Passing a more privileged role to a service is a common "
                    "way to gain permissions the identity does not hold itself. Whether that is "
                    "possible also depends on which services the identity can start, which is not "
                    "established here."
                ),
                remediation=(
                    f"Limit iam:PassRole for {identity.name} to the specific role ARNs it needs to "
                    "hand to services, and add the iam:PassedToService condition where it applies. "
                    "Confirm deployments still work before applying the change."
                ),
            )
        )
    return drafts