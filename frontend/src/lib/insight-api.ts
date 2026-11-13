import { requestJson, segment, send } from "@/lib/api";
import type {
  Dashboard,
  PermissionList,
  Report,
  RunComparison,
} from "@/lib/insight-types";

function runPath(environmentId: string, runId: string): string {
  return `/environments/${segment(environmentId)}/analysis-runs/${segment(runId)}`;
}

export function getDashboard(signal?: AbortSignal): Promise<Dashboard> {
  return requestJson<Dashboard>("/dashboard", { signal });
}

export function compareRuns(
  environmentId: string,
  baseRunId: string,
  targetRunId: string,
  signal?: AbortSignal,
): Promise<RunComparison> {
  return requestJson<RunComparison>(`/environments/${segment(environmentId)}/comparison`, {
    query: { base_run_id: baseRunId, target_run_id: targetRunId },
    signal,
  });
}

export function getReport(
  environmentId: string,
  runId: string,
  signal?: AbortSignal,
): Promise<Report> {
  return requestJson<Report>(`${runPath(environmentId, runId)}/report`, { signal });
}

export async function downloadReportMarkdown(
  environmentId: string,
  runId: string,
): Promise<Blob> {
  const response = await send(`${runPath(environmentId, runId)}/report/markdown`);
  return response.blob();
}

export function listPermissions(
  environmentId: string,
  runId: string,
  signal?: AbortSignal,
): Promise<PermissionList> {
  return requestJson<PermissionList>(`${runPath(environmentId, runId)}/permissions`, { signal });
}