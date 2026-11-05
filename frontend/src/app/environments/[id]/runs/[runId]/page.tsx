"use client";

import { SEVERITY_STYLES } from "@/components/analysis/SeverityBadge";
import { Section } from "@/components/ui/Section";
import { formatDateTime } from "@/lib/format";
import { SEVERITY_ORDER } from "@/lib/labels";
import { useRun } from "@/lib/run-context";

export default function RunOverviewPage() {
  const run = useRun();

  return (
    <div className="space-y-6">
      {run.status === "failed" && (
        <p
          role="alert"
          className="rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-300"
        >
          This analysis run failed and produced no results. Check the backend logs.
        </p>
      )}
      <div className="grid grid-cols-5 gap-3">
        {SEVERITY_ORDER.map((severity) => (
          <div key={severity} className="rounded-lg border border-line bg-panel p-4">
            <p className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium capitalize ${SEVERITY_STYLES[severity]}`}>
              {severity}
            </p>
            <p className="mt-2 text-3xl font-semibold text-white">{run.severity_counts[severity]}</p>
          </div>
        ))}
      </div>
      <Section title="Run details">
        <dl className="grid grid-cols-[10rem_1fr] gap-y-2 text-sm">
          <dt className="text-slate-500">Findings</dt>
          <dd className="text-slate-200">{run.finding_count}</dd>
          <dt className="text-slate-500">Import</dt>
          <dd className="text-slate-200">
            {run.import_source} ({formatDateTime(run.import_created_at)})
          </dd>
          <dt className="text-slate-500">Started</dt>
          <dd className="text-slate-200">{formatDateTime(run.started_at)}</dd>
          <dt className="text-slate-500">Completed</dt>
          <dd className="text-slate-200">
            {run.completed_at ? formatDateTime(run.completed_at) : "not completed"}
          </dd>
        </dl>
      </Section>
      <Section title="What this analysis does not cover">
        <ul className="list-disc space-y-2 pl-5 text-sm text-slate-300">
          {run.limitations.map((limitation) => (
            <li key={limitation}>{limitation}</li>
          ))}
        </ul>
      </Section>
    </div>
  );
}