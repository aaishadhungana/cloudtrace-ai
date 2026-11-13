from collections import defaultdict
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnalysisRun, Finding, Identity, Policy, Resource
from app.models.enums import Effect
from app.schemas.permissions import FindingRef, IdentityRef, PermissionEntry, PermissionList

StatementKey = tuple[str, str, int]


def _statement_keys(evidence: list[dict[str, Any]]) -> set[StatementKey]:
    keys: set[StatementKey] = set()

    def add(item: Any) -> None:
        if not isinstance(item, dict):
            return
        kind = item.get("kind")
        owner = item.get("owner")
        index = item.get("statement_index")
        if (
            isinstance(kind, str)
            and kind.endswith("_statement")
            and isinstance(owner, str)
            and isinstance(index, int)
        ):
            keys.add((kind.removesuffix("_statement"), owner, index))

    for item in evidence:
        add(item)
        for field in ("granted_by", "denied_by"):
            for ref in item.get(field) or []:
                add(ref)
    return keys


def _entry(
    kind: str,
    source_name: str,
    owner: str,
    index: int,
    statement: dict[str, Any],
    target_label: str,
    targets: list[str],
    identities: list[IdentityRef],
    findings_by_key: dict[StatementKey, list[FindingRef]],
) -> PermissionEntry:
    return PermissionEntry(
        key=f"{kind}:{owner}:{index}",
        source_kind=kind,
        source_name=source_name,
        source_owner=owner,
        statement_index=index,
        sid=statement.get("sid"),
        effect=Effect(statement["effect"]),
        actions=list(statement.get("actions", [])),
        target_label=target_label,
        targets=list(targets),
        conditions=statement.get("conditions") or {},
        related_identities=identities,
        related_findings=findings_by_key.get((kind, owner, index), []),
    )


def list_permissions(db: Session, run: AnalysisRun, limit: int, offset: int) -> PermissionList:
    identities = list(
        db.scalars(
            select(Identity)
            .where(Identity.import_id == run.import_id)
            .order_by(Identity.name, Identity.external_id)
        )
    )
    resources = list(
        db.scalars(
            select(Resource)
            .where(Resource.import_id == run.import_id)
            .order_by(Resource.name, Resource.external_id)
        )
    )
    policies = list(
        db.scalars(
            select(Policy)
            .where(Policy.import_id == run.import_id)
            .order_by(Policy.name, Policy.external_id)
        )
    )
    findings = list(
        db.scalars(
            select(Finding)
            .where(Finding.analysis_run_id == run.id)
            .order_by(Finding.risk_score.desc(), Finding.rule_id, Finding.title)
        )
    )

    findings_by_key: dict[StatementKey, list[FindingRef]] = defaultdict(list)
    for finding in findings:
        reference = FindingRef(
            id=finding.id, title=finding.title, severity=finding.severity, rule_id=finding.rule_id
        )
        for key in _statement_keys(finding.evidence):
            findings_by_key[key].append(reference)

    attached: dict[str, list[IdentityRef]] = defaultdict(list)
    for identity in identities:
        for policy_id in identity.attributes.get("policy_ids", []):
            attached[policy_id].append(IdentityRef(id=identity.id, name=identity.name))

    entries: list[PermissionEntry] = []
    for policy in policies:
        for index, statement in enumerate(policy.statements):
            entries.append(
                _entry(
                    "policy",
                    policy.name,
                    policy.external_id,
                    index,
                    statement,
                    "resources",
                    statement.get("resources", []),
                    attached.get(policy.external_id, []),
                    findings_by_key,
                )
            )
    for identity in identities:
        trust = identity.attributes.get("trust_policy")
        if not trust:
            continue
        for index, statement in enumerate(trust["statements"]):
            entries.append(
                _entry(
                    "trust",
                    identity.name,
                    identity.external_id,
                    index,
                    statement,
                    "principals",
                    statement.get("principals", []),
                    [IdentityRef(id=identity.id, name=identity.name)],
                    findings_by_key,
                )
            )
    for resource in resources:
        resource_policy = resource.attributes.get("resource_policy")
        if not resource_policy:
            continue
        for index, statement in enumerate(resource_policy["statements"]):
            entries.append(
                _entry(
                    "resource_policy",
                    resource.name,
                    resource.external_id,
                    index,
                    statement,
                    "principals",
                    statement.get("principals", []),
                    [],
                    findings_by_key,
                )
            )
    return PermissionList(total=len(entries), items=entries[offset : offset + limit])