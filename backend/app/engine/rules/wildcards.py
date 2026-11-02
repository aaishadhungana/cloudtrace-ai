from app.engine.context import AnalysisContext
from app.engine.evidence import statement_evidence
from app.engine.fingerprint import make_fingerprint, statement_digest
from app.engine.rules.base import FindingDraft, RuleInfo
from app.engine.rules.shared import (
    CONDITION_NOTE,
    is_admin_statement,
    is_wildcard_statement,
    policy_statements,
)
from app.engine.scoring import Capability, assess

ADMIN_INFO = RuleInfo(
    rule_id="CT-IAM-001",
    title="Wildcard administrative permissions",
    description="An identity is allowed every action on all resources through an attached policy.",
    finding_type="wildcard_admin",
)

SERVICE_INFO = RuleInfo(
    rule_id="CT-IAM-002",
    title="Service-wide wildcard on broad resources",
    description="An identity is allowed every action of a service on broad resource patterns.",
    finding_type="service_wildcard",
)


def detect_admin_wildcard(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    drafts: list[FindingDraft] = []
    for identity in snapshot.identities:
        for ref, statement in policy_statements(snapshot, identity):
            if not is_admin_statement(snapshot, statement):
                continue
            policy = snapshot.policies[ref.owner]
            assessment = assess(
                Capability.ADMIN_WILDCARD,
                reaches_sensitive=context.reaches_sensitive(identity.arn),
                can_write=context.can_write(identity.arn),
                conditional=statement.has_conditions,
            )
            explanation = (
                f"{identity.name} is granted every action on all resources by policy "
                f"'{policy.name}'. That is full administrative access inside the modeled account. "
                "If this identity is compromised, everything it can reach is exposed."
            )
            if statement.has_conditions:
                explanation += CONDITION_NOTE
            drafts.append(
                FindingDraft(
                    rule_id=ADMIN_INFO.rule_id,
                    finding_type=ADMIN_INFO.finding_type,
                    title=f"{identity.name} has wildcard administrative permissions",
                    fingerprint=make_fingerprint(
                        ADMIN_INFO.rule_id, identity.arn, ref.owner, statement_digest(statement)
                    ),
                    identity_arn=identity.arn,
                    resource_arn=None,
                    assessment=assessment,
                    evidence=[
                        statement_evidence(snapshot, ref),
                        *context.sensitive_access_evidence(identity.arn),
                    ],
                    explanation=explanation,
                    remediation=(
                        f"Replace the '*' action in statement {ref.index} of policy "
                        f"'{policy.name}' with the specific actions this identity needs, and limit "
                        "its resources to specific ARNs. Keep administrator access on a small number "
                        "of dedicated identities. Confirm the narrower policy still covers the "
                        "required workflows before applying it."
                    ),
                )
            )
    return drafts


def detect_service_wildcard(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    drafts: list[FindingDraft] = []
    for identity in snapshot.identities:
        for ref, statement in policy_statements(snapshot, identity):
            if not is_wildcard_statement(snapshot, statement):
                continue
            if is_admin_statement(snapshot, statement):
                continue
            policy = snapshot.policies[ref.owner]
            services = ", ".join(
                sorted({action.split(":")[0] for action in statement.actions if action.endswith(":*")})
            )
            assessment = assess(
                Capability.SERVICE_WILDCARD,
                reaches_sensitive=context.reaches_sensitive(identity.arn),
                can_write=context.can_write(identity.arn),
                conditional=statement.has_conditions,
            )
            explanation = (
                f"{identity.name} is granted every {services} action on broad resources by policy "
                f"'{policy.name}'. Service-wide access is usually much wider than a workload needs."
            )
            if statement.has_conditions:
                explanation += CONDITION_NOTE
            drafts.append(
                FindingDraft(
                    rule_id=SERVICE_INFO.rule_id,
                    finding_type=SERVICE_INFO.finding_type,
                    title=f"{identity.name} has service-wide {services} permissions",
                    fingerprint=make_fingerprint(
                        SERVICE_INFO.rule_id, identity.arn, ref.owner, statement_digest(statement)
                    ),
                    identity_arn=identity.arn,
                    resource_arn=None,
                    assessment=assessment,
                    evidence=[
                        statement_evidence(snapshot, ref),
                        *context.sensitive_access_evidence(identity.arn),
                    ],
                    explanation=explanation,
                    remediation=(
                        f"Replace the wildcard {services} actions in statement {ref.index} of policy "
                        f"'{policy.name}' with the specific actions required, and limit resources to "
                        "specific ARNs. Confirm the narrower policy still covers the required "
                        "workflows before applying it."
                    ),
                )
            )
    return drafts