import type { Decision } from "@/lib/analysis-types";
import { DECISION_LABELS } from "@/lib/labels";

const STYLES: Record<Decision, string> = {
  allowed: "bg-amber-500/15 text-amber-300",
  conditional: "bg-sky-500/15 text-sky-300",
  explicitly_denied: "bg-emerald-500/15 text-emerald-300",
  not_allowed: "bg-slate-500/20 text-slate-300",
};

export function DecisionBadge({ decision }: { decision: Decision }) {
  return (
    <span className={`inline-block rounded-full px-2.5 py-0.5 text-xs font-medium ${STYLES[decision]}`}>
      {DECISION_LABELS[decision]}
    </span>
  );
}