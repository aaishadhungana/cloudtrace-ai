"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { useCallback, useState } from "react";
import { ComparisonResult } from "@/components/comparison/ComparisonResult";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { inputClass } from "@/components/ui/styles";
import { listRuns } from "@/lib/analysis-api";
import { formatDateTime } from "@/lib/format";
import { useApiResource } from "@/lib/use-api-resource";

export default function ComparePage() {
  const { id } = useParams<{ id: string }>();
  const loadRuns = useCallback((signal: AbortSignal) => listRuns(id, signal), [id]);
  const { state } = useApiResource(loadRuns);
  const [baseChoice, setBaseChoice] = useState("");
  const [targetChoice, setTargetChoice] = useState("");

  const completed =
    state.kind === "ready" ? state.data.filter((run) => run.status === "completed") : [];
  const targetId = targetChoice || completed[0]?.id || "";
  const baseId = baseChoice || completed[1]?.id || "";

  function options() {
    return completed.map((run) => (
      <option key={run.id} value={run.id}>
        {formatDateTime(run.started_at)} · {run.finding_count} findings · {run.attack_path_count}{" "}
        paths
      </option>
    ));
  }

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <Link
        href={`/environments/${id}`}
        className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden />
        Environment
      </Link>
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-white">Compare runs</h1>
        <p className="mt-1 text-sm text-slate-400">
          Compare an earlier run with a later one to see what changed. Items are matched by stable
          fingerprints. A finding that disappears is reported as no longer detected, never as
          resolved.
        </p>
      </header>
      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && completed.length < 2 && (
        <p className="text-sm text-slate-400">
          At least two completed runs are needed. Import a changed configuration and run the
          analysis again.
        </p>
      )}
      {state.kind === "ready" && completed.length >= 2 && (
        <>
          <div className="flex flex-wrap items-end gap-4">
            <div className="space-y-1">
              <label htmlFor="base-run" className="block text-xs text-slate-500">
                Base run (earlier)
              </label>
              <select
                id="base-run"
                className={inputClass}
                value={baseId}
                onChange={(event) => setBaseChoice(event.target.value)}
              >
                {options()}
              </select>
            </div>
            <div className="space-y-1">
              <label htmlFor="target-run" className="block text-xs text-slate-500">
                Target run (later)
              </label>
              <select
                id="target-run"
                className={inputClass}
                value={targetId}
                onChange={(event) => setTargetChoice(event.target.value)}
              >
                {options()}
              </select>
            </div>
          </div>
          {baseId === targetId ? (
            <p className="text-sm text-amber-300">Choose two different runs.</p>
          ) : (
            <ComparisonResult environmentId={id} baseRunId={baseId} targetRunId={targetId} />
          )}
        </>
      )}
    </div>
  );
}