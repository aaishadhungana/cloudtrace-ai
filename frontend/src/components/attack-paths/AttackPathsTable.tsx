import Link from "next/link";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import { ClassificationBadge } from "@/components/attack-paths/ClassificationBadge";
import type { AttackPathSummary } from "@/lib/attack-path-types";

interface AttackPathsTableProps {
  paths: AttackPathSummary[];
  basePath: string;
  emptyMessage?: string;
}

export function AttackPathsTable({ paths, basePath, emptyMessage }: AttackPathsTableProps) {
  if (paths.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-line p-8 text-center">
        <p className="text-sm text-slate-400">{emptyMessage ?? "No attack paths."}</p>
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
            <th className="px-4 py-2 font-medium">Class</th>
            <th className="px-4 py-2 font-medium">Path</th>
            <th className="px-4 py-2 font-medium">Steps</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {paths.map((path) => (
            <tr key={path.id} className="align-top hover:bg-white/5">
              <td className="px-4 py-3">
                <SeverityBadge severity={path.severity} />
              </td>
              <td className="px-4 py-3 font-mono text-slate-200">{path.risk_score}</td>
              <td className="px-4 py-3">
                <ClassificationBadge classification={path.classification} />
              </td>
              <td className="px-4 py-3">
                <Link
                  href={`${basePath}/attack-paths/${path.id}`}
                  className="text-slate-100 hover:text-accent"
                >
                  {path.start_identity_name} to {path.target_resource_name}
                </Link>
                <p className="mt-0.5 text-xs text-slate-500">{path.summary}</p>
              </td>
              <td className="px-4 py-3 font-mono text-slate-400">{path.step_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}