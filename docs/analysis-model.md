# Analysis model v1.0

CloudTrace AI evaluates a documented IAM-inspired subset. It is not a reimplementation of AWS IAM.

## Evaluation decisions

| Decision | Meaning |
|---|---|
| `allowed` | An unconditional Allow applies and no Deny applies. |
| `conditional` | An Allow applies only through statements with conditions, or a conditional Deny applies, or the grant depends on an external account that is not modeled. |
| `explicitly_denied` | An Allow applies, but an unconditional Deny also applies. Deny wins. |
| `not_allowed` | No Allow applies (implicit deny). |

Conditions are never evaluated, because the engine has no request context. A conditional Deny does not block.

## Matching

- Actions are case-insensitive, with `*` as a wildcard.
- Resources are case-sensitive, with `*` and `?` as wildcards.
- Storage object actions (`s3:GetObject`, `s3:PutObject`, `s3:DeleteObject`) are checked against `<bucket arn>/*`. Bucket actions are checked against the bucket ARN.
- A resource pattern is **broad** when it is `*`, has a wildcard in its name segment, or matches two or more modeled identities or resources.

## Effective relationships

Computed for every identity against every identity and resource in the import: `can_read`, `can_write`, `can_modify_policy`, `can_assume`, `can_pass_role`. Resource policies are combined with identity policies. Unconditional Allow from either side is enough within the primary account.

- **Role assumption.** A trust-policy Allow naming the principal (or `*`) is enough inside the primary account. An identity-side Deny blocks it. For external principals the result is `conditional`.
- **Primary account.** The most common account among non-external identities. Identities in another account, and `external_principal` identities, are external.
- **Persisted relationships.** Only Allow and explicit-Deny outcomes are kept.

## Rules

| ID | Detects |
|---|---|
| CT-IAM-001 | Allow `*` on broad resources |
| CT-IAM-002 | Allow `service:*` on broad resources |
| CT-IAM-003 | Sensitive resource reached through a broad pattern (when not already covered by 001 or 002) |
| CT-IAM-004 | Trust policy allows `*` |
| CT-IAM-005 | Trust policy allows an external principal |
| CT-IAM-006 | IAM policy-modification permissions (not reported for 001 identities) |
| CT-IAM-007 | `iam:PassRole` on a broad pattern (not reported for 001 identities) |
| CT-IAM-008 | Resource policy allows `*` |
| CT-IAM-009 | Resource policy allows an external principal |
| CT-IAM-010 | Sensitive resource blocked only by an explicit Deny |

Rule IDs are stable. Fingerprints are built from the rule, the subject and a hash of the statement content.

## Risk score

`score = clamp(sum(factors), 0, 100)`. Severity is derived from the score only.

| Factor | Points |
|---|---|
| Capability | admin wildcard 45, policy modification 45, trust any principal 40, public write 40, service wildcard 30, cross-account trust 30, public read 30, sensitive broad grant 25, pass role wildcard 24, cross-account resource grant 15, deny dependency 8 |
| Exposure | public +25, external +10 |
| Reaches a sensitive resource | +25 |
| Write or modify capability | +10 |
| Role chain involved | +5 |
| Grant restricted by conditions | -10 |

Bands: 80 and above is critical, 60 to 79 high, 40 to 59 medium, 20 to 39 low, below 20 info.

A high score means a risky configuration. It does not mean confirmed exploitability.

## Limitations

- Permission boundaries, service control policies, session policies and inline policies are not modeled.
- Resources of type `other` and actions outside the action catalog are not evaluated.
- External accounts are not modeled.
- Statement-level rules flag the grant itself. A Deny that cancels a grant shows up in the effective relationships.