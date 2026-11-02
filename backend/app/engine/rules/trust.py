from app.engine.context import AnalysisContext
from app.engine.evidence import statement_evidence
from app.engine.fingerprint import make_fingerprint, statement_digest
from app.engine.models import EFFECT_ALLOW, PUBLIC_PRINCIPAL, TRUST_KIND, StatementRef
from app.engine.rules.base import FindingDraft, RuleInfo
from app.engine.rules.shared import CONDITION_NOTE
from app.engine.scoring import Capability, Exposure, assess

TRUST_ANY_INFO = RuleInfo(
    rule_id="CT-IAM-004",
    title="Role trust policy allows any principal",
    description="A role trust policy allows the '*' principal to assume the role.",
    finding_type="trust_any_principal",
)

CROSS_ACCOUNT_TRUST_INFO = RuleInfo(
    rule_id="CT-IAM-005",
    title="Role trust policy allows an external principal",
    description="A role trust policy allows a principal from outside the modeled account.",
    finding_type="cross_account_trust",
)


def detect_trust_any_principal(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    drafts: list[FindingDraft] = []
    for identity in snapshot.identities:
        trust = identity.trust_policy
        if trust is None:
            continue
        for index, statement in enumerate(trust.statements):
            if statement.effect != EFFECT_ALLOW or PUBLIC_PRINCIPAL not in statement.principals:
                continue
            ref = StatementRef(TRUST_KIND, identity.arn, index)
            assessment = assess(
                Capability.TRUST_ANY_PRINCIPAL,
                exposure=Exposure.PUBLIC,
                reaches_sensitive=context.reaches_sensitive(identity.arn),
                can_write=context.can_write(identity.arn),
                role_chain=True,
                conditional=statement.has_conditions,
            )
            explanation = (
                f"The trust policy of role {identity.name} allows any principal ('*') to assume it. "
                "Anyone who can reach the role assumption API is allowed by this statement, so the "
                "role's permissions are exposed to every caller the rest of the setup lets through."
            )
            if statement.has_conditions:
                explanation += CONDITION_NOTE
            drafts.append(
                FindingDraft(
                    rule_id=TRUST_ANY_INFO.rule_id,
                    finding_type=TRUST_ANY_INFO.finding_type,
                    title=f"Role {identity.name} can be assumed by any principal",
                    fingerprint=make_fingerprint(
                        TRUST_ANY_INFO.rule_id, identity.arn, statement_digest(statement)
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
                        f"Replace the '*' principal in statement {index} of the trust policy of "
                        f"{identity.name} with the specific identities that need to assume it. If "
                        "outside access is required, add a condition such as aws:PrincipalOrgID. "
                        "Confirm the legitimate callers still work before applying the change."
                    ),
                )
            )
    return drafts


def detect_cross_account_trust(context: AnalysisContext) -> list[FindingDraft]:
    snapshot = context.snapshot
    drafts: list[FindingDraft] = []
    for identity in snapshot.identities:
        trust = identity.trust_policy
        if trust is None:
            continue
        for index, statement in enumerate(trust.statements):
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
            ref = StatementRef(TRUST_KIND, identity.arn, index)
            assessment = assess(
                Capability.CROSS_ACCOUNT_TRUST,
                exposure=Exposure.EXTERNAL,
                reaches_sensitive=context.reaches_sensitive(identity.arn),
                can_write=context.can_write(identity.arn),
                role_chain=True,
                conditional=statement.has_conditions,
            )
            listed = ", ".join(external)
            explanation = (
                f"Role {identity.name} can be assumed by principals outside the primary account "
                f"({listed}). Access held by those accounts is outside this analysis, so the "
                "result reflects the trust configuration only."
            )
            if statement.has_conditions:
                explanation += CONDITION_NOTE
            drafts.append(
                FindingDraft(
                    rule_id=CROSS_ACCOUNT_TRUST_INFO.rule_id,
                    finding_type=CROSS_ACCOUNT_TRUST_INFO.finding_type,
                    title=f"Role {identity.name} trusts an external account",
                    fingerprint=make_fingerprint(
                        CROSS_ACCOUNT_TRUST_INFO.rule_id, identity.arn, statement_digest(statement)
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
                        "Confirm the external account needs this role and limit the role's "
                        "permissions to the minimum. Add a trust condition such as "
                        "aws:PrincipalOrgID where it fits the integration. Verify the integration "
                        "still works before applying the change."
                    ),
                )
            )
    return drafts