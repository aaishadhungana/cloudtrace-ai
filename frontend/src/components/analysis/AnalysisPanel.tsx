"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { GitCompare, Play } from "lucide-react";
import { useCallback, useState } from "react";
import { SeverityCountsBar } from "@/components/analysis/SeverityBadge";
import { Button } from "@/components/ui/Button";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { cardClass } from "@/components/ui/styles";
import { listRuns, startAnalysis } from "@/lib/analysis-api";
import { formatDateTime } from "@/lib/format";
import { useApiResource } from "@/lib/use-api-resource";

interface AnalysisPanelProps {
  environmentId: string;
  hasImport: boolean;
}

export function AnalysisPanel({ environmentId, hasImport }: AnalysisPanelProps) {
  const router = useRouter();
  const loadRuns = useCallback(
    (signal: AbortSignal) => listRuns(environmentId, signal),
    [environmentId],
  );
  const { state, reload } = useApiResource(loadRuns);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const completedCount =
    state.kind === "ready" ? state.data.filter((run) => run.status === "completed").length : 0;

  async function handleStart() {
    setStarting(true);
    setError(null);
    try {
      const run = await startAnalysis(environmentId);
      reload();
      router.push(`/environments/${environmentId}/runs/${run.id}`);
    } catch (caught) {
      setError(caught);
      setStarting(false);
    }
  }

  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between gap-4">
        <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
          Analysis runs
        </h2>
        <div className="flex items-center gap-3">
          {completedCount >= 2 && (
            <Link
              href={`/environments/${environmentId}/compare`}
              className="inline-flex items-center gap-1.5 text-sm text-accent hover:underline"
            >
              <GitCompare className="h-4 w-4" aria-hidden />
              Compare runs
            </Link>
          )}
          <Button loading={starting} disabled={!hasImport} onClick={handleStart}>
            <Play className="h-4 w-4" aria-hidden />
            Run analysis
          </Button>
        </div>
      </div>
      {!hasImport && (
        <p className="text-sm text-slate-500">Import a configuration to run an analysis.</p>
      )}
      {error !== null && <ErrorBanner error={error} />}
      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && state.data.length === 0 && hasImport && (
        <div className="rounded-lg border border-dashed border-line p-6 text-center">
          <p className="text-sm text-slate-400">No analysis runs yet.</p>
        </div>
      )}
      {state.kind === "ready" &&
        state.data.map((run) => (
          <Link
            key={run.id}
            href={`/environments/${environmentId}/runs/${run.id}`}
            className={`${cardClass} flex items-center justify-between gap-4 transition-colors hover:border-accent/50`}
          >
            <div>
              <p className="text-sm font-medium text-white">{formatDateTime(run.started_at)}</p>
              <p className="text-xs text-slate-500">
                <span className="capitalize">{run.status}</span> · engine {run.analysis_version} ·{" "}
                {run.finding_count} findings · {run.attack_path_count} paths
              </p>
            </div>
            <SeverityCountsBar counts={run.severity_counts} />
          </Link>
        ))}
    </section>
  );
}