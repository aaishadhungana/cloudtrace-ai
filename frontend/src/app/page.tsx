"use client";

import Link from "next/link";
import { BackendStatus } from "@/components/BackendStatus";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Section } from "@/components/ui/Section";
import { Spinner } from "@/components/ui/Spinner";
import { getDashboard } from "@/lib/insight-api";
import { formatDateTime } from "@/lib/format";
import { useApiResource } from "@/lib/use-api-resource";

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border border-line bg-panel p-4">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className="mt-2 text-3xl font-semibold text-white">{value}</p>
    </div>
  );
}

export default function OverviewPage() {
  const { state } = useApiResource(getDashboard);

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-white">Overview</h1>
        <p className="mt-1 text-sm text-slate-400">
          Cloud identity security and attack-path analysis. Figures come from the latest completed
          analysis run of each environment.
        </p>
      </header>

      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && (
        <>
          {state.data.environment_count === 0 && (
            <div className="rounded-lg border border-dashed border-line p-8 text-center">
              <p className="text-sm text-slate-400">
                No environments yet.{" "}
                <Link href="/environments" className="text-accent hover:underline">
                  Create your first environment
                </Link>
                .
              </p>
            </div>
          )}
          {state.data.environment_count > 0 && state.data.analyzed_environment_count === 0 && (
            <div className="rounded-lg border border-dashed border-line p-8 text-center">
              <p className="text-sm text-slate-400">
                No completed analysis yet.{" "}
                <Link href="/environments" className="text-accent hover:underline">
                  Import a configuration and run an analysis
                </Link>
                .
              </p>
            </div>
          )}
          <div className="grid grid-cols-3 gap-3">
            <Stat label="Environments" value={state.data.environment_count} />
            <Stat label="Identities" value={state.data.identity_count} />
            <Stat label="Sensitive resources" value={state.data.sensitive_resource_count} />
            <Stat label="Open findings" value={state.data.open_finding_count} />
            <Stat label="Critical and high" value={state.data.critical_high_finding_count} />
            <Stat label="Attack paths" value={state.data.attack_path_count} />
          </div>

          <Section title="Highest-priority findings">
            {state.data.top_findings.length === 0 && (
              <p className="text-sm text-slate-500">No findings to show.</p>
            )}
            <ul className="space-y-2">
              {state.data.top_findings.map((finding) => (
                <li key={finding.finding_id} className="flex flex-wrap items-center gap-3 text-sm">
                  <SeverityBadge severity={finding.severity} />
                  <span className="font-mono text-xs text-slate-400">{finding.risk_score}</span>
                  <Link
                    href={`/environments/${finding.environment_id}/runs/${finding.run_id}/findings/${finding.finding_id}`}
                    className="text-slate-100 hover:text-accent"
                  >
                    {finding.title}
                  </Link>
                  <span className="text-xs text-slate-500">{finding.environment_name}</span>
                </li>
              ))}
            </ul>
          </Section>

          <Section title="Recent analysis runs">
            {state.data.recent_runs.length === 0 && (
              <p className="text-sm text-slate-500">No analysis runs yet.</p>
            )}
            <ul className="space-y-2">
              {state.data.recent_runs.map((run) => (
                <li key={run.run_id} className="flex flex-wrap items-center gap-3 text-sm">
                  <Link
                    href={`/environments/${run.environment_id}/runs/${run.run_id}`}
                    className="text-slate-100 hover:text-accent"
                  >
                    {run.environment_name}
                  </Link>
                  <span className="text-xs text-slate-500">
                    {formatDateTime(run.started_at)} ·{" "}
                    <span className={run.status === "failed" ? "text-red-300" : ""}>
                      {run.status}
                    </span>{" "}
                    · {run.finding_count} findings · {run.attack_path_count} paths
                  </span>
                </li>
              ))}
            </ul>
          </Section>
        </>
      )}
      <BackendStatus />
    </div>
  );
}