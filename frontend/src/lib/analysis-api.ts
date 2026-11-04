import { requestJson, segment } from "@/lib/api";
import type {
  AnalysisRun,
  AnalysisRunDetail,
  FindingDetail,
  FindingList,
  FindingQuery,
  IdentityDetail,
  IdentitySummary,
  Rule,
} from "@/lib/analysis-types";

function runsPath(environmentId: string): string {
  return `/environments/${segment(environmentId)}/analysis-runs`;
}

function runPath(environmentId: string, runId: string): string {
  return `${runsPath(environmentId)}/${segment(runId)}`;
}

export function startAnalysis(environmentId: string): Promise<AnalysisRun> {
  return requestJson<AnalysisRun>(runsPath(environmentId), { method: "POST" });
}

export function listRuns(environmentId: string, signal?: AbortSignal): Promise<AnalysisRun[]> {
  return requestJson<AnalysisRun[]>(runsPath(environmentId), { signal });
}

export function getRun(
  environmentId: string,
  runId: string,
  signal?: AbortSignal,
): Promise<AnalysisRunDetail> {
  return requestJson<AnalysisRunDetail>(runPath(environmentId, runId), { signal });
}

export function listFindings(
  environmentId: string,
  runId: string,
  query: FindingQuery = {},
  signal?: AbortSignal,
): Promise<FindingList> {
  const params: Record<string, string> = {};
  if (query.severity) {
    params.severity = query.severity;
  }
  if (query.ruleId) {
    params.rule_id = query.ruleId;
  }
  if (query.sort) {
    params.sort = query.sort;
  }
  return requestJson<FindingList>(`${runPath(environmentId, runId)}/findings`, {
    query: params,
    signal,
  });
}

export function getFinding(
  environmentId: string,
  runId: string,
  findingId: string,
  signal?: AbortSignal,
): Promise<FindingDetail> {
  return requestJson<FindingDetail>(
    `${runPath(environmentId, runId)}/findings/${segment(findingId)}`,
    { signal },
  );
}

export function listIdentities(
  environmentId: string,
  runId: string,
  signal?: AbortSignal,
): Promise<IdentitySummary[]> {
  return requestJson<IdentitySummary[]>(`${runPath(environmentId, runId)}/identities`, { signal });
}

export function getIdentity(
  environmentId: string,
  runId: string,
  identityId: string,
  signal?: AbortSignal,
): Promise<IdentityDetail> {
  return requestJson<IdentityDetail>(
    `${runPath(environmentId, runId)}/identities/${segment(identityId)}`,
    { signal },
  );
}

export function listRules(signal?: AbortSignal): Promise<Rule[]> {
  return requestJson<Rule[]>("/rules", { signal });
}