import type { RiskFactor } from "@/lib/analysis-types";

interface RiskFactorListProps {
  factors: RiskFactor[];
  score: number;
  rawScore: number;
}

export function RiskFactorList({ factors, score, rawScore }: RiskFactorListProps) {
  return (
    <div className="space-y-2">
      <ul className="divide-y divide-line text-sm">
        {factors.map((factor) => (
          <li key={factor.name} className="flex items-start justify-between gap-4 py-2">
            <span className="text-slate-300">{factor.detail}</span>
            <span
              className={`shrink-0 font-mono ${factor.points < 0 ? "text-emerald-300" : "text-slate-100"}`}
            >
              {factor.points > 0 ? `+${factor.points}` : factor.points}
            </span>
          </li>
        ))}
      </ul>
      <p className="flex justify-between border-t border-line pt-2 text-sm font-medium text-white">
        <span>Risk score</span>
        <span className="font-mono">
          {score}
          {rawScore !== score ? ` (raw ${rawScore}, capped)` : ""}
        </span>
      </p>
    </div>
  );
}