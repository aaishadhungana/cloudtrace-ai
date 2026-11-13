"use client";

import Link from "next/link";
import { useCallback } from "react";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Section } from "@/components/ui/Section";
import { Spinner } from "@/components/ui/Spinner";
import { compareRuns } from "@/lib/insight-api";
import type { ComparisonStatus, RunSide, StatusCounts } from "@/lib/insight-types";
import { formatDateTime } from "@/lib/format";
import { useApiResource } from "@/lib/use-api-resource";

const STATUS_LABELS: Record<ComparisonStatus, string> = {
  new: "New",
  persisting: "Persisting",
  no_longer_detected: "No longer detected",
  not_comparable: "Not comparable",
};

const STATUS_STYLES: Record<ComparisonStatus, string> = {
  new: "bg-red-500/15 text-red-300",
  persisting: "bg-slate-500/20 text-slate-300",
  no_longer_detected: "bg-emerald-500/15 text-emerald-300",
  not_comparable: "bg-amber-500/15 text-amber-300",
};

const STATUS_ORDER: ComparisonStatus[] = [
  "new",
  "persisting",
  "no_longer_detected",
  "not_comparable",
];

function StatusBadge({ status }: { status: ComparisonStatus }) {
  return (
    <span
      className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ${STATUS_STYLES[status]}`}
    >
      {STATUS_LABELS[status]}
    </span>
  );
}

function Counts({ counts }: { counts: StatusCounts }) {
  return (
    <div className="flex flex-wrap gap-2">
      {STATUS_ORDER.map((status) => (
        <span
          key={status}
          className={`rounded-full px-2.5 py-0.5 text-xs font-medium ${STATUS_STYLES[status]}`}
        >
          {counts[status]} {STATUS_LABELS[status].toLowerCase()}
        </span>
      ))}
    </div>
  );
}

function score(base: number | null, target: number | null): string {
  return `${base ?? "none"} to ${target ?? "none"}`;
}

function SideTable({ base, target }: { base: RunSide; target: RunSide }) {
  const rows: { label: string; base: string; target: string }[] = [
    { label: "Run started", base: formatDateTime(base.started_at), target: formatDateTime(target.started_at) },
    { label: "Import", base: base.import_source, target: target.import_source },
    { label: "Engine version", base: base.analysis_version, target: target.analysis_version },
    { label: "Findings", base: String(base.finding_count), target: String(target.finding_count) },
    {
      label: "Critical and high",
      base: String(base.high_risk_finding_count),
      target: String(target.high_risk_finding_count),
    },
    {
      label: "Attack paths",
      base: String(base.attack_path_count),
      target: String(target.attack_path_count),
    },
  ];
  return (
    <table className="w-full text-left text-sm">
      <thead className="text-xs uppercase tracking-wide text-slate-500">
        <tr>
          <th className="py-2 font-medium" />
          <th className="py-2 font-medium">Base run</th>
          <th className="py-2 font-medium">Target run</th>
        </tr>
      </thead>
      <tbody className="divide-y divide-line">
        {rows.map((row) => (
          <tr key={row.label}>
            <td className="py-2 text-slate-500">{row.label}</td>
            <td className="py-2 text-slate-200">{row.base}</td>
            <td className="py-2 text-slate-200">{row.target}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

interface ComparisonResultProps {
  environmentId: string;
  baseRunId: string;
  targetRunId: string;
}

export function ComparisonResult({ environmentId, baseRunId, targetRunId }: ComparisonResultProps) {
  const loadComparison = useCallback(
    (signal: AbortSignal) => compareRuns(environmentId, baseRunId, targetRunId, signal),
    [environmentId, baseRunId, targetRunId],
  );
  const { state } = useApiResource(loadComparison);

  if (state.kind === "loading") {
    return <Spinner label="Comparing runs" />;
  }
  if (state.kind === "error") {
    return <ErrorBanner error={state.error} />;
  }
  const result = state.data;
  const runBase = `/environments/${environmentId}/runs`;

  return (
    <div className="space-y-6">
      <Section title="Caveats">
        <ul className="list-disc space-y-2 pl-5 text-sm text-amber-200">
          {result.caveats.map((caveat) => (
            <li key={caveat}>{caveat}</li>
          ))}
        </ul>
      </Section>

      <Section title="Runs">
        <SideTable base={result.base} target={result.target} />
      </Section>

      <Section title="Findings">
        <Counts counts={result.finding_counts} />
        <ul className="space-y-2">
          {result.findings.map((item) => {
            const targetId = item.target_finding_id;
            const href = targetId
              ? `${runBase}/${result.target.run_id}/findings/${targetId}`
              : `${runBase}/${result.base.run_id}/findings/${item.base_finding_id}`;
            return (
              <li key={item.fingerprint} className="rounded-md border border-line bg-ink p-3">
                <div className="flex flex-wrap items-center gap-3">
                  <StatusBadge status={item.status} />
                  <SeverityBadge severity={item.severity} />
                  <Link href={href} className="text-sm text-slate-100 hover:text-accent">
                    {item.title}
                  </Link>
                  <span className="font-mono text-xs text-slate-500">
                    score {score(item.base_score, item.target_score)}
                  </span>
                </div>
                {item.reason && <p className="mt-1 text-xs text-slate-400">{item.reason}</p>}
              </li>
            );
          })}
          {result.findings.length === 0 && (
            <li className="text-sm text-slate-500">Neither run has findings.</li>
          )}
        </ul>
      </Section>

      <Section title="Attack paths">
        <Counts counts={result.path_counts} />
        <ul className="space-y-2">
          {result.attack_paths.map((item) => {
            const targetId = item.target_path_id;
            const href = targetId
              ? `${runBase}/${result.target.run_id}/attack-paths/${targetId}`
              : `${runBase}/${result.base.run_id}/attack-paths/${item.base_path_id}`;
            return (
              <li key={item.fingerprint} className="rounded-md border border-line bg-ink p-3">
                <div className="flex flex-wrap items-center gap-3">
                  <StatusBadge status={item.status} />
                  <Link href={href} className="text-sm text-slate-100 hover:text-accent">
                    {item.summary}
                  </Link>
                  <span className="font-mono text-xs text-slate-500">
                    score {score(item.base_score, item.target_score)}
                  </span>
                </div>
                {item.reason && <p className="mt-1 text-xs text-slate-400">{item.reason}</p>}
              </li>
            );
          })}
          {result.attack_paths.length === 0 && (
            <li className="text-sm text-slate-500">Neither run has attack paths.</li>
          )}
        </ul>
      </Section>
    </div>
  );
}