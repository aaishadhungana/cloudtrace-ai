"use client";

import { useParams } from "next/navigation";
import { useCallback, useState } from "react";
import { AttackPathsTable } from "@/components/attack-paths/AttackPathsTable";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { inputClass } from "@/components/ui/styles";
import { listAttackPaths } from "@/lib/attack-path-api";
import type { PathClassification, PathSort } from "@/lib/attack-path-types";
import { useRun } from "@/lib/run-context";
import { useApiResource } from "@/lib/use-api-resource";

export default function AttackPathsPage() {
  const { id, runId } = useParams<{ id: string; runId: string }>();
  const run = useRun();
  const [classification, setClassification] = useState<PathClassification | "">("");
  const [sort, setSort] = useState<PathSort>("score_desc");

  const loadPaths = useCallback(
    (signal: AbortSignal) =>
      listAttackPaths(id, runId, { classification: classification || undefined, sort }, signal),
    [id, runId, classification, sort],
  );
  const { state } = useApiResource(loadPaths);

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-400">
        Paths from an identity through role assumption or role passing to a resource marked
        sensitive. A path is a chain of modeled permissions. It does not prove an attacker can
        exploit it.
      </p>
      {run.paths_incomplete && (
        <p
          role="status"
          className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200"
        >
          Discovery reached a limit, so this list may not be complete.
        </p>
      )}
      <div className="flex flex-wrap items-end gap-4">
        <div className="space-y-1">
          <label htmlFor="class-filter" className="block text-xs text-slate-500">
            Class
          </label>
          <select
            id="class-filter"
            className={inputClass}
            value={classification}
            onChange={(event) => setClassification(event.target.value as PathClassification | "")}
          >
            <option value="">All</option>
            <option value="supported">Supported</option>
            <option value="potential">Potential</option>
          </select>
        </div>
        <div className="space-y-1">
          <label htmlFor="path-sort" className="block text-xs text-slate-500">
            Sort
          </label>
          <select
            id="path-sort"
            className={inputClass}
            value={sort}
            onChange={(event) => setSort(event.target.value as PathSort)}
          >
            <option value="score_desc">Highest score</option>
            <option value="score_asc">Lowest score</option>
          </select>
        </div>
      </div>
      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && (
        <>
          <p className="text-xs text-slate-500">
            Showing {state.data.items.length} of {state.data.total}
          </p>
          <AttackPathsTable
            paths={state.data.items}
            basePath={`/environments/${id}/runs/${runId}`}
            emptyMessage="No attack paths were found. This does not prove the sensitive resources are safe. See the limitations on the Overview tab."
          />
        </>
      )}
    </div>
  );
}