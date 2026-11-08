import { requestJson, segment } from "@/lib/api";
import type {
  AttackPathDetail,
  AttackPathList,
  AttackPathQuery,
} from "@/lib/attack-path-types";

function pathsPath(environmentId: string, runId: string): string {
  return `/environments/${segment(environmentId)}/analysis-runs/${segment(runId)}/attack-paths`;
}

export function listAttackPaths(
  environmentId: string,
  runId: string,
  query: AttackPathQuery = {},
  signal?: AbortSignal,
): Promise<AttackPathList> {
  const params: Record<string, string> = {};
  if (query.classification) {
    params.classification = query.classification;
  }
  if (query.minScore !== undefined) {
    params.min_score = String(query.minScore);
  }
  if (query.startIdentityId) {
    params.start_identity_id = query.startIdentityId;
  }
  if (query.targetResourceId) {
    params.target_resource_id = query.targetResourceId;
  }
  if (query.sort) {
    params.sort = query.sort;
  }
  return requestJson<AttackPathList>(pathsPath(environmentId, runId), { query: params, signal });
}

export function getAttackPath(
  environmentId: string,
  runId: string,
  pathId: string,
  signal?: AbortSignal,
): Promise<AttackPathDetail> {
  return requestJson<AttackPathDetail>(
    `${pathsPath(environmentId, runId)}/${segment(pathId)}`,
    { signal },
  );
}