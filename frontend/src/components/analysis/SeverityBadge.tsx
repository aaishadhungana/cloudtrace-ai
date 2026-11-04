import type { Severity, SeverityCounts } from "@/lib/analysis-types";
import { SEVERITY_ORDER } from "@/lib/labels";

export const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-red-500/15 text-red-300",
  high: "bg-orange-500/15 text-orange-300",
  medium: "bg-amber-500/15 text-amber-300",
  low: "bg-sky-500/15 text-sky-300",
  info: "bg-slate-500/20 text-slate-300",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${SEVERITY_STYLES[severity]}`}
    >
      {severity}
    </span>
  );
}

export function SeverityCountsBar({ counts }: { counts: SeverityCounts }) {
  const visible = SEVERITY_ORDER.filter((severity) => counts[severity] > 0);
  if (visible.length === 0) {
    return <span className="text-xs text-slate-500">No findings</span>;
  }
  return (
    <div className="flex flex-wrap gap-1.5">
      {visible.map((severity) => (
        <span
          key={severity}
          className={`rounded-full px-2 py-0.5 text-xs font-medium ${SEVERITY_STYLES[severity]}`}
        >
          {counts[severity]} {severity}
        </span>
      ))}
    </div>
  );
}