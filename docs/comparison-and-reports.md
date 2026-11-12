# Comparison, reports and dashboard

## Comparing runs

`GET /environments/{id}/comparison?base_run_id=...&target_run_id=...` compares two completed runs of one environment.

Findings and attack paths are matched by fingerprint. Fingerprints come from rule, identity and resource ARNs and statement content, not from database ids or statement order.

| Status | Meaning |
|---|---|
| new | Only in the target run |
| persisting | In both runs (a changed score is noted) |
| no_longer_detected | Only in the base run, and its identities and resources are still in the target import |
| not_comparable | Only in the base run, and one of its identities or resources is not in the target import |

CloudTrace AI never labels anything "resolved". The engine only knows what it still reports. The response lists caveats: a different engine version, incomplete path discovery, items that cannot be compared, and a reminder that fewer findings does not mean secure.

## Report

`GET .../analysis-runs/{run_id}/report` returns the report as data. `.../report/markdown` downloads it as Markdown.

It contains the environment, analysis scope (import and modeled counts), finding counts, up to 25 highest-priority findings with their remediation, up to 15 attack paths, the limitations, and the generation time. A stored AI summary appears in its own labeled section, only if one exists. Imported text is escaped in the Markdown.

## Dashboard

`GET /dashboard` summarizes the latest completed run of each of the user's environments: identities, sensitive resources, open findings, critical and high findings, attack paths, the five most recent runs, and the eight highest-scoring findings.