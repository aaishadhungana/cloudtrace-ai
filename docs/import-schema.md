# Import schema v1.0

CloudTrace AI imports a single JSON document describing a simulated AWS-style account. The schema is IAM-inspired. It is not full AWS IAM.

## Top level

| Field | Required | Notes |
|---|---|---|
| `schema_version` | yes | Must be `"1.0"` |
| `identities` | yes | 1 to 500 items |
| `resources` | no | Up to 500 items |
| `policies` | no | Up to 500 items |

Every object rejects unknown fields. Nothing is silently ignored.

## Identities

`arn`, `name`, `type` (`iam_user`, `iam_role`, `service`, `external_principal`), optional `account_id` (12 digits, must match the ARN account when both are present), optional `policy_ids`, and `trust_policy` for roles only.

External principals cannot have policies. Their permissions are outside the modeled account.

## Resources

`arn`, `name`, `type` (`storage_bucket`, `compute`, `secret`, `database`, `other`), `sensitive` (boolean, default false), optional `account_id`, and optional `resource_policy`.

## Policies

`id`, `name`, and 1 to 50 `statements`. A statement has `effect` (`Allow` or `Deny`), `actions`, `resources`, optional `conditions` and optional `sid`.

- Actions look like `s3:GetObject`, `s3:*` or `*`.
- Resources are `*` or an ARN pattern where `*` and `?` are wildcards.
- `NotAction`, `NotResource`, `NotPrincipal` and policy variables are not supported. They are rejected.

## Trust and resource policies

Statements have `effect`, `principals`, `actions`, optional `conditions` and optional `sid`.

- Principals are `*` or the ARN of an identity declared in the same document. Cross-account principals must be declared as `external_principal`.
- Trust policies support only `sts:AssumeRole`.
- A role without a `trust_policy` means trust information was not provided. It does not mean nobody can assume the role.

## Conditions

Operators: `StringEquals`, `StringLike`, `IpAddress`, `Bool`. Keys: `aws:SourceIp`, `aws:MultiFactorAuthPresent`, `aws:PrincipalOrgID`. Anything else is rejected.

## Limits

Body size 1 MiB (`IMPORT_MAX_BYTES`), 50 statements per policy, 100 items per statement list, 512 characters per string.

## Storage

Identities, resources and policies are stored as rows. Trust and resource policies are stored in `attributes`. The import record keeps counts and a SHA-256 of the uploaded bytes, not the raw document.