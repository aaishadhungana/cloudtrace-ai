from app.engine.catalog import RESOURCE_CATALOG, WRITE_TYPES
from app.engine.context import AnalysisContext
from app.engine.evidence import statement_evidence
from app.engine.fingerprint import make_fingerprint, statement_digest
from app.engine.matching import matches_action
from app.engine.models import (
    EFFECT_ALLOW,
    PUBLIC_PRINCIPAL,
    RESOURCE_POLICY_KIND,
    PrincipalStatement,
    ResourceNode,
    StatementRef,
)
from app.engine.rules.base import FindingDraft, RuleInfo
from app.engine.rules.shared import CONDITION_NOTE
from app.engine.scoring import Capability, Exposure, assess
from app.models.enums import RelationshipType

PUBLIC_RESOURCE_INFO = RuleInfo(
    rule_id="CT-IAM-008",
    title="Resource policy grants public access",
    description="A resource policy allows the '*' principal to perform actions on the resource.",
    finding_type="public_resource",
)

CROSS_ACCOUNT_RESOURCE_INFO = RuleInfo(
    rule_id="CT-IAM-009",
    title="Resource policy grants an external principal access",
    description="A resource policy allows a principal from outside the modeled account.",
    finding_type="cross_account_resource_grant",
)


def _granted_types(resource: ResourceNode, statement: PrincipalStatement) -> list[RelationshipType]:
    catalog = RESOURCE_CATALOG.get(resource.resource_type, {})
    return [
        relationship_type
        for relationship_type, specs in catalog.items()
        if any(
            matches_action(pattern, spec.action)
            for pattern in statement.actions
            for spec in specs
        )
    ]


def detect_public_resource(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    drafts: list[FindingDraft] = []
    for resource in snapshot.resources:
        policy = resource.resource_policy
        if policy is None:
            continue
        for index, statement in enumerate(policy.statements):
            if statement.effect != EFFECT_ALLOW or PUBLIC_PRINCIPAL not in statement.principals:
                continue
            granted = _granted_types(resource, statement)
            writes = any(item in WRITE_TYPES for item in granted)
            capability = Capability.PUBLIC_WRITE if writes else Capability.PUBLIC_READ
            assessment = assess(
                capability,
                exposure=Exposure.PUBLIC,
                reaches_sensitive=resource.is_sensitive,
                conditional=statement.has_conditions,
            )
            ref = StatementRef(RESOURCE_POLICY_KIND, resource.arn, index)
            actions = ", ".join(statement.actions)
            explanation = (
                f"The resource policy of {resource.name} allows any principal ('*') to perform "
                f"{actions}."
            )
            if resource.is_sensitive:
                explanation += " The resource is marked sensitive."
            if not granted:
                explanation += (
                    " The actions are not in the built-in action catalog, so they are treated "
                    "as read exposure."
                )
            if statement.has_conditions:
                explanation += CONDITION_NOTE
            drafts.append(
                FindingDraft(
                    rule_id=PUBLIC_RESOURCE_INFO.rule_id,
                    finding_type=PUBLIC_RESOURCE_INFO.finding_type,
                    title=f"{resource.name} allows public access",
                    fingerprint=make_fingerprint(
                        PUBLIC_RESOURCE_INFO.rule_id, resource.arn, statement_digest(statement)
                    ),
                    identity_arn=None,
                    resource_arn=resource.arn,
                    assessment=assessment,
                    evidence=[statement_evidence(snapshot, ref)],
                    explanation=explanation,
                    remediation=(
                        f"Remove the '*' principal from statement {index} of the resource policy of "
                        f"{resource.name}, or replace it with the specific principals that need "
                        "access. If public access is intended, keep sensitive data out of the "
                        "resource and limit the allowed actions to the minimum."
                    ),
                )
            )
    return drafts


def detect_cross_account_resource_grant(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    drafts: list[FindingDraft] = []
    for resource in snapshot.resources:
        policy = resource.resource_policy
        if policy is None:
            continue
        for index, statement in enumerate(policy.statements):
            if statement.effect != EFFECT_ALLOW:
                continue
            external = [
                principal
                for principal in statement.principals
                if principal != PUBLIC_PRINCIPAL
                and principal in snapshot.identity_index
                and snapshot.is_external(snapshot.identity_index[principal])
            ]
            if not external:
                continue
            granted = _granted_types(resource, statement)
            assessment = assess(
                Capability.CROSS_ACCOUNT_RESOURCE_GRANT,
                exposure=Exposure.EXTERNAL,
                reaches_sensitive=resource.is_sensitive,
                can_write=any(item in WRITE_TYPES for item in granted),
                conditional=statement.has_conditions,
            )
            ref = StatementRef(RESOURCE_POLICY_KIND, resource.arn, index)
            explanation = (
                f"The resource policy of {resource.name} grants {', '.join(statement.actions)} to "
                f"principals outside the primary account ({', '.join(external)}). Permissions held "
                "in those accounts are not modeled."
            )
            if statement.has_conditions:
                explanation += CONDITION_NOTE
            drafts.append(
                FindingDraft(
                    rule_id=CROSS_ACCOUNT_RESOURCE_INFO.rule_id,
                    finding_type=CROSS_ACCOUNT_RESOURCE_INFO.finding_type,
                    title=f"{resource.name} grants access to an external account",
                    fingerprint=make_fingerprint(
                        CROSS_ACCOUNT_RESOURCE_INFO.rule_id, resource.arn, statement_digest(statement)
                    ),
                    identity_arn=None,
                    resource_arn=resource.arn,
                    assessment=assessment,
                    evidence=[statement_evidence(snapshot, ref)],
                    explanation=explanation,
                    remediation=(
                        "Confirm each external principal needs this access, limit the allowed "
                        "actions to the minimum, and add conditions such as aws:PrincipalOrgID where "
                        "they fit. Verify the integration still works before applying the change."
                    ),
                )
            )
    return drafts