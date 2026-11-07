# Permission graph and attack paths

## Graph

Nodes are identities and resources. A directed edge exists only for an effective Allow with decision `allowed` or `conditional`. Explicit Deny creates no edge.

| Edge | Direction | Meaning |
|---|---|---|
| `can_assume` | identity to role | Trust policy (and identity policy) allow assumption |
| `can_pass_role` | identity to role | `iam:PassRole` is allowed |
| `can_read`, `can_write`, `can_modify_policy` | identity to resource | Access to the resource |

When two identities have both `can_assume` and `can_pass_role`, the graph keeps one edge: assume before pass-role, then allowed before conditional. Policy modification between identities is not a graph edge.

## Paths

A path starts at an identity, has at least one pivot, and ends at a resource marked sensitive. Search uses `networkx.all_simple_edge_paths`, so a node never repeats and cycles cannot loop.

A path is skipped when the start identity, or any identity before the last one, already has unconditional direct access to the target.

Limits: 5 steps, 3 paths per start and target pair, 200 paths per run, 500 candidates per pair. When a limit hides something, the run is marked `paths_incomplete`.

## Classification

| Class | Rule |
|---|---|
| `supported` | Every step is `allowed`, and uses only assume, read or write |
| `potential` | Any step is `conditional`, or any step is `iam:PassRole` |

Paths that cannot be established are not stored. Neither class proves exploitability.

## Path risk score

`score = clamp(sum(factors), 0, 100)`

| Factor | Points |
|---|---|
| Ends at a sensitive resource | +25 |
| Final access from a wildcard or broad grant | +20 |
| Final step can write or change policy | +10 |
| Path has 2 steps / 3 steps | +10 / +5 |
| Start identity outside the modeled account | +15 |
| A role on the path trusts any principal | +20 |
| A step is conditional | -10 |
| A step relies on PassRole | -10 |

Severity bands match findings: 80 critical, 60 high, 40 medium, 20 low.

## Not modeled

Policy modification as a pivot, administrative roles as targets, session chaining, and the ability to start services. A missing path does not prove a resource is safe.