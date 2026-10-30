import ipaddress
from typing import Annotated, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, StringConstraints

from app.ingest import limits
from app.models.enums import IdentityType, ResourceType

SUPPORTED_SCHEMA_VERSION = "1.0"
SUPPORTED_CONDITION_OPERATORS = frozenset({"StringEquals", "StringLike", "IpAddress", "Bool"})
SUPPORTED_CONDITION_KEYS = frozenset(
    {"aws:SourceIp", "aws:MultiFactorAuthPresent", "aws:PrincipalOrgID"}
)

CONCRETE_ARN = r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{0,12}:[A-Za-z0-9_/:.+=@-]+"
ARN_PATTERN = r"arn:aws:[a-z0-9*-]+:[a-z0-9*-]*:[0-9*]{0,12}:[A-Za-z0-9_/:.+=@*?-]+"

ShortText = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=limits.MAX_STRING_LENGTH),
]
ConcreteArn = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, max_length=limits.MAX_STRING_LENGTH, pattern=f"^{CONCRETE_ARN}$"
    ),
]
ResourcePattern = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        max_length=limits.MAX_STRING_LENGTH,
        pattern=f"^(\\*|{ARN_PATTERN})$",
    ),
]
PrincipalRef = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        max_length=limits.MAX_STRING_LENGTH,
        pattern=f"^(\\*|{CONCRETE_ARN})$",
    ),
]
ActionPattern = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        max_length=limits.MAX_STRING_LENGTH,
        pattern=r"^(\*|[a-z0-9-]+:[A-Za-z0-9*]+)$",
    ),
]
AccountId = Annotated[str, StringConstraints(pattern=r"^[0-9]{12}$")]
PolicyId = Annotated[
    str, StringConstraints(strip_whitespace=True, pattern=r"^[A-Za-z0-9_.-]{1,128}$")
]


def validate_conditions(
    value: dict[str, dict[str, str | list[str]]],
) -> dict[str, dict[str, str | list[str]]]:
    for operator, clauses in value.items():
        if operator not in SUPPORTED_CONDITION_OPERATORS:
            supported = ", ".join(sorted(SUPPORTED_CONDITION_OPERATORS))
            raise ValueError(
                f"Unsupported condition operator '{operator}'. Supported operators: {supported}"
            )
        for key, raw_values in clauses.items():
            if key not in SUPPORTED_CONDITION_KEYS:
                supported = ", ".join(sorted(SUPPORTED_CONDITION_KEYS))
                raise ValueError(
                    f"Unsupported condition key '{key}'. Supported keys: {supported}"
                )
            values = [raw_values] if isinstance(raw_values, str) else raw_values
            if not values or len(values) > limits.MAX_ITEMS_PER_STATEMENT:
                raise ValueError(f"Condition '{key}' must have between 1 and 100 values")
            for item in values:
                if not item or len(item) > limits.MAX_STRING_LENGTH:
                    raise ValueError(f"Condition '{key}' contains an empty or oversized value")
                if operator == "Bool" and item not in {"true", "false"}:
                    raise ValueError("Bool conditions accept only 'true' or 'false'")
                if operator == "IpAddress":
                    try:
                        ipaddress.ip_network(item, strict=False)
                    except ValueError as error:
                        raise ValueError(f"'{item}' is not a valid IP address or CIDR") from error
    return value


Conditions = Annotated[
    dict[str, dict[str, str | list[str]]], AfterValidator(validate_conditions)
]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class PolicyStatement(StrictModel):
    sid: ShortText | None = None
    effect: Literal["Allow", "Deny"]
    actions: Annotated[
        list[ActionPattern], Field(min_length=1, max_length=limits.MAX_ITEMS_PER_STATEMENT)
    ]
    resources: Annotated[
        list[ResourcePattern], Field(min_length=1, max_length=limits.MAX_ITEMS_PER_STATEMENT)
    ]
    conditions: Conditions = Field(default_factory=dict)


class PrincipalStatement(StrictModel):
    sid: ShortText | None = None
    effect: Literal["Allow", "Deny"]
    principals: Annotated[
        list[PrincipalRef], Field(min_length=1, max_length=limits.MAX_ITEMS_PER_STATEMENT)
    ]
    actions: Annotated[
        list[ActionPattern], Field(min_length=1, max_length=limits.MAX_ITEMS_PER_STATEMENT)
    ]
    conditions: Conditions = Field(default_factory=dict)


class PrincipalPolicy(StrictModel):
    statements: Annotated[
        list[PrincipalStatement],
        Field(min_length=1, max_length=limits.MAX_STATEMENTS_PER_POLICY),
    ]


class PolicyDefinition(StrictModel):
    id: PolicyId
    name: ShortText
    statements: Annotated[
        list[PolicyStatement],
        Field(min_length=1, max_length=limits.MAX_STATEMENTS_PER_POLICY),
    ]


class IdentityDefinition(StrictModel):
    arn: ConcreteArn
    name: ShortText
    type: IdentityType
    account_id: AccountId | None = None
    policy_ids: Annotated[
        list[PolicyId], Field(max_length=limits.MAX_POLICY_IDS_PER_IDENTITY)
    ] = Field(default_factory=list)
    trust_policy: PrincipalPolicy | None = None


class ResourceDefinition(StrictModel):
    arn: ConcreteArn
    name: ShortText
    type: ResourceType
    sensitive: bool = False
    account_id: AccountId | None = None
    resource_policy: PrincipalPolicy | None = None


class ImportDocument(StrictModel):
    schema_version: Literal["1.0"]
    identities: Annotated[
        list[IdentityDefinition], Field(min_length=1, max_length=limits.MAX_IDENTITIES)
    ]
    resources: Annotated[
        list[ResourceDefinition], Field(max_length=limits.MAX_RESOURCES)
    ] = Field(default_factory=list)
    policies: Annotated[
        list[PolicyDefinition], Field(max_length=limits.MAX_POLICIES)
    ] = Field(default_factory=list)