"use client";

import { useCallback } from "react";
import { AttackPathsTable } from "@/components/attack-paths/AttackPathsTable";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { listAttackPaths } from "@/lib/attack-path-api";
import { useApiResource } from "@/lib/use-api-resource";

interface RelatedAttackPathsProps {
  environmentId: string;
  runId: string;
  startIdentityId?: string;
  targetResourceId?: string;
}

export function RelatedAttackPaths({
  environmentId,
  runId,
  startIdentityId,
  targetResourceId,
}: RelatedAttackPathsProps) {
  const loadPaths = useCallback(
    (signal: AbortSignal) =>
      listAttackPaths(environmentId, runId, { startIdentityId, targetResourceId }, signal),
    [environmentId, runId, startIdentityId, targetResourceId],
  );
  const { state } = useApiResource(loadPaths);

  if (state.kind === "loading") {
    return <Spinner />;
  }
  if (state.kind === "error") {
    return <ErrorBanner error={state.error} />;
  }
  return (
    <AttackPathsTable
      paths={state.data.items}
      basePath={`/environments/${environmentId}/runs/${runId}`}
      emptyMessage="No attack paths were found for this."
    />
  );
}