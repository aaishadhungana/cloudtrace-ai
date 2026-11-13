import { requestJson, segment } from "@/lib/api";
import type {
  AIAnalysis,
  AIStatus,
  AttackPathAnalysisContent,
  FindingAnalysisContent,
  SecuritySummaryContent,
} from "@/lib/ai-types";

function aiPath(environmentId: string, runId: string): string {
  return `/environments/${segment(environmentId)}/analysis-runs/${segment(runId)}/ai`;
}

function refreshQuery(refresh: boolean): Record<string, string> | undefined {
  return refresh ? { refresh: "true" } : undefined;
}

export function getAiStatus(
  environmentId: string,
  runId: string,
  signal?: AbortSignal,
): Promise<AIStatus> {
  return requestJson<AIStatus>(`${aiPath(environmentId, runId)}/status`, { signal });
}

export function getFindingAnalysis(
  environmentId: string,
  runId: string,
  findingId: string,
  signal?: AbortSignal,
): Promise<AIAnalysis<FindingAnalysisContent> | null> {
  return requestJson<AIAnalysis<FindingAnalysisContent> | null>(
    `${aiPath(environmentId, runId)}/findings/${segment(findingId)}`,
    { signal },
  );
}

export function createFindingAnalysis(
  environmentId: string,
  runId: string,
  findingId: string,
  refresh: boolean,
): Promise<AIAnalysis<FindingAnalysisContent>> {
  return requestJson<AIAnalysis<FindingAnalysisContent>>(
    `${aiPath(environmentId, runId)}/findings/${segment(findingId)}`,
    { method: "POST", query: refreshQuery(refresh) },
  );
}

export function getPathAnalysis(
  environmentId: string,
  runId: string,
  pathId: string,
  signal?: AbortSignal,
): Promise<AIAnalysis<AttackPathAnalysisContent> | null> {
  return requestJson<AIAnalysis<AttackPathAnalysisContent> | null>(
    `${aiPath(environmentId, runId)}/attack-paths/${segment(pathId)}`,
    { signal },
  );
}

export function createPathAnalysis(
  environmentId: string,
  runId: string,
  pathId: string,
  refresh: boolean,
): Promise<AIAnalysis<AttackPathAnalysisContent>> {
  return requestJson<AIAnalysis<AttackPathAnalysisContent>>(
    `${aiPath(environmentId, runId)}/attack-paths/${segment(pathId)}`,
    { method: "POST", query: refreshQuery(refresh) },
  );
}

export function getSummaryAnalysis(
  environmentId: string,
  runId: string,
  signal?: AbortSignal,
): Promise<AIAnalysis<SecuritySummaryContent> | null> {
  return requestJson<AIAnalysis<SecuritySummaryContent> | null>(
    `${aiPath(environmentId, runId)}/summary`,
    { signal },
  );
}

export function createSummaryAnalysis(
  environmentId: string,
  runId: string,
  refresh: boolean,
): Promise<AIAnalysis<SecuritySummaryContent>> {
  return requestJson<AIAnalysis<SecuritySummaryContent>>(
    `${aiPath(environmentId, runId)}/summary`,
    { method: "POST", query: refreshQuery(refresh) },
  );
}