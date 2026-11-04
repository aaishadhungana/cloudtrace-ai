import Link from "next/link";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import type { FindingSummary } from "@/lib/analysis-types";

interface FindingsTableProps {
  findings: FindingSummary[];
  basePath: string;
}

export function FindingsTable({ findings, basePath }: FindingsTableProps) {
  if (findings.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-line p-8 text-center">
        <p className="text-sm text-slate-400">No findings match.</p>
      </div>
    );
  }
  return (
    <div className="overflow-x-auto rounded-lg border border-line">
      <table className="w-full text-left text-sm">
        <thead className="bg-panel text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-4 py-2 font-medium">Severity</th>
            <th className="px-4 py-2 font-medium">Score</th>
            <th className="px-4 py-2 font-medium">Finding</th>
            <th className="px-4 py-2 font-medium">Rule</th>
            <th className="px-4 py-2 font-medium">Affected</th>
            <th className="px-4 py-2 font-medium">Status</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {findings.map((finding) => (
            <tr key={finding.id} className="hover:bg-white/5">
              <td className="px-4 py-3">
                <SeverityBadge severity={finding.severity} />
              </td>
              <td className="px-4 py-3 font-mono text-slate-200">{finding.risk_score}</td>
              <td className="px-4 py-3">
                <Link
                  href={`${basePath}/findings/${finding.id}`}
                  className="text-slate-100 hover:text-accent"
                >
                  {finding.title}
                </Link>
              </td>
              <td className="px-4 py-3 font-mono text-xs text-slate-400">{finding.rule_id}</td>
              <td className="px-4 py-3 text-slate-300">
                {finding.identity_name ?? finding.resource_name ?? "none"}
              </td>
              <td className="px-4 py-3 capitalize text-slate-400">{finding.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}