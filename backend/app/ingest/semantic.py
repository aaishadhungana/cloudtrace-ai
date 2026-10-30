from app.ingest import limits
from app.ingest.parser import ImportIssue
from app.ingest.schema import (
    IdentityDefinition,
    ImportDocument,
    PrincipalPolicy,
    ResourceDefinition,
)
from app.models.enums import IdentityType

TRUST_ACTION = "sts:AssumeRole"


def validate_semantics(document: ImportDocument) -> list[ImportIssue]:
    issues: list[ImportIssue] = []
    identity_arns = _unique_values(
        "identities", "arn", [item.arn for item in document.identities], issues
    )
    resource_arns = _unique_values(
        "resources", "arn", [item.arn for item in document.resources], issues
    )
    policy_ids = _unique_values(
        "policies", "id", [item.id for item in document.policies], issues
    )
    for arn in sorted(identity_arns & resource_arns):
        issues.append(
            ImportIssue(
                path="resources",
                message=f"ARN '{arn}' is defined as both an identity and a resource",
            )
        )
    for index, identity in enumerate(document.identities):
        _validate_identity(index, identity, policy_ids, identity_arns, issues)
    for index, resource in enumerate(document.resources):
        _validate_resource(index, resource, identity_arns, issues)
    return issues[: limits.MAX_REPORTED_ISSUES]


def _unique_values(
    collection: str, field: str, values: list[str], issues: list[ImportIssue]
) -> set[str]:
    seen: set[str] = set()
    for index, value in enumerate(values):
        if value in seen:
            issues.append(
                ImportIssue(
                    path=f"{collection}[{index}].{field}",
                    message=f"Duplicate {field} '{value}'",
                )
            )
        seen.add(value)
    return seen


def _check_account(
    path: str, arn: str, account_id: str | None, issues: list[ImportIssue]
) -> None:
    arn_account = arn.split(":")[4]
    if account_id is not None and arn_account and arn_account != account_id:
        issues.append(
            ImportIssue(
                path=f"{path}.account_id",
                message=(
                    f"account_id '{account_id}' does not match the account "
                    f"'{arn_account}' in the ARN"
                ),
            )
        )


def _check_principals(
    path: str,
    policy: PrincipalPolicy,
    identity_arns: set[str],
    issues: list[ImportIssue],
) -> None:
    for statement_index, statement in enumerate(policy.statements):
        for principal_index, principal in enumerate(statement.principals):
            if principal != "*" and principal not in identity_arns:
                issues.append(
                    ImportIssue(
                        path=f"{path}.statements[{statement_index}].principals[{principal_index}]",
                        message=(
                            f"Principal '{principal}' is not defined in identities. "
                            "Declare external principals with type 'external_principal'."
                        ),
                    )
                )


def _check_trust_actions(
    path: str, policy: PrincipalPolicy, issues: list[ImportIssue]
) -> None:
    for statement_index, statement in enumerate(policy.statements):
        for action_index, action in enumerate(statement.actions):
            if action != TRUST_ACTION:
                issues.append(
                    ImportIssue(
                        path=f"{path}.statements[{statement_index}].actions[{action_index}]",
                        message="Trust policies only support 'sts:AssumeRole' in schema version 1.0",
                    )
                )


def _validate_identity(
    index: int,
    identity: IdentityDefinition,
    policy_ids: set[str],
    identity_arns: set[str],
    issues: list[ImportIssue],
) -> None:
    path = f"identities[{index}]"
    _check_account(path, identity.arn, identity.account_id, issues)
    if identity.type is IdentityType.EXTERNAL_PRINCIPAL and identity.policy_ids:
        issues.append(
            ImportIssue(
                path=f"{path}.policy_ids",
                message=(
                    "Policies cannot be attached to external principals; "
                    "their permissions are outside the modeled account"
                ),
            )
        )
    for position, policy_id in enumerate(identity.policy_ids):
        if policy_id not in policy_ids:
            issues.append(
                ImportIssue(
                    path=f"{path}.policy_ids[{position}]",
                    message=f"References unknown policy '{policy_id}'",
                )
            )
    if identity.trust_policy is None:
        return
    if identity.type is not IdentityType.IAM_ROLE:
        issues.append(
            ImportIssue(
                path=f"{path}.trust_policy",
                message="trust_policy is only valid for identities of type 'iam_role'",
            )
        )
        return
    trust_path = f"{path}.trust_policy"
    _check_principals(trust_path, identity.trust_policy, identity_arns, issues)
    _check_trust_actions(trust_path, identity.trust_policy, issues)


def _validate_resource(
    index: int,
    resource: ResourceDefinition,
    identity_arns: set[str],
    issues: list[ImportIssue],
) -> None:
    path = f"resources[{index}]"
    _check_account(path, resource.arn, resource.account_id, issues)
    if resource.resource_policy is not None:
        _check_principals(f"{path}.resource_policy", resource.resource_policy, identity_arns, issues)