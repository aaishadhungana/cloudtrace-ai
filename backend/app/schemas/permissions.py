import uuid
from typing import Any, Literal

from pydantic import BaseModel

from app.models.enums import Effect, Severity


class IdentityRef(BaseModel):
    id: uuid.UUID
    name: str


class FindingRef(BaseModel):
    id: uuid.UUID
    title: str
    severity: Severity
    rule_id: str


class PermissionEntry(BaseModel):
    key: str
    source_kind: Literal["policy", "trust", "resource_policy"]
    source_name: str
    source_owner: str
    statement_index: int
    sid: str | None
    effect: Effect
    actions: list[str]
    target_label: Literal["resources", "principals"]
    targets: list[str]
    conditions: dict[str, Any]
    related_identities: list[IdentityRef]
    related_findings: list[FindingRef]


class PermissionList(BaseModel):
    total: int
    items: list[PermissionEntry]