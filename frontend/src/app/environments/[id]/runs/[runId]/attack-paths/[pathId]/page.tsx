"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { useCallback, useState } from "react";
import { DecisionBadge } from "@/components/analysis/DecisionBadge";
import { RiskFactorList } from "@/components/analysis/RiskFactorList";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import { ClassificationBadge } from "@/components/attack-paths/ClassificationBadge";
import { PathGraph } from "@/components/attack-paths/PathGraph";
import type { Selection } from "@/components/attack-paths/PathGraph";
import { PathInspector } from "@/components/attack-paths/PathInspector";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Section } from "@/components/ui/Section";
import { Spinner } from "@/components/ui/Spinner";
import { getAttackPath } from "@/lib/attack-path-api";
import type { PathClassification } from "@/lib/attack-path-types";
import { RELATIONSHIP_LABELS } from "@/lib/labels";
import { useApiResource } from "@/lib/use-api-resource";

const CLASSIFICATION_TEXT: Record<PathClassification, string> = {
  supported:
    "Every step is allowed by the modeled permissions. This does not confirm the path is exploitable.",
  potential:
    "At least one step depends on conditions or an unverified assumption. Verify those before treating the path as real.",
};

export default function AttackPathDetailPage() {
  const { id, runId, pathId } = useParams<{ id: string; runId: string; pathId: string }>();
  const base = `/environments/${id}/runs/${runId}`;
  const [selection, setSelection] = useState<Selection>(null);
  const loadPath = useCallback(
    (signal: AbortSignal) => getAttackPath(id, runId, pathId, signal),
    [id, runId, pathId],
  );
  const { state } = useApiResource(loadPath);

  return (
    <div className="space-y-6">
      <Link
        href={`${base}/attack-paths`}
        className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden />
        Attack paths
      </Link>
      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && (
        <>
          <header className="space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <SeverityBadge severity={state.data.severity} />
              <ClassificationBadge classification={state.data.classification} />
              <span className="font-mono text-sm text-slate-300">
                Risk score {state.data.risk_score}/100
              </span>
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-white">
              {state.data.start_identity_name} to {state.data.target_resource_name}
            </h1>
            <p className="text-sm text-slate-300">{state.data.summary}</p>
            <p className="text-xs text-slate-500">
              {CLASSIFICATION_TEXT[state.data.classification]}
            </p>
          </header>

          <PathGraph path={state.data} selection={selection} onSelect={setSelection} />

          <Section title="Inspector">
            <PathInspector path={state.data} selection={selection} basePath={base} />
          </Section>

          <Section title="Steps">
            <ol className="space-y-2">
              {state.data.edges.map((edge, index) => {
                const source = state.data.nodes[index];
                const target = state.data.nodes[index + 1];
                const active = selection?.kind === "edge" && selection.index === index;
                return (
                  <li key={`${edge.source}-${edge.target}`}>
                    <button
                      type="button"
                      onClick={() => setSelection({ kind: "edge", index })}
                      aria-pressed={active}
                      className={`flex w-full flex-wrap items-center gap-3 rounded-md border px-3 py-2 text-left text-sm transition-colors ${
                        active
                          ? "border-accent bg-accent/10"
                          : "border-line hover:bg-white/5"
                      }`}
                    >
                      <span className="font-mono text-xs text-slate-500">{index + 1}</span>
                      <span className="text-slate-200">
                        {source.name} to {target.name}
                      </span>
                      <span className="text-xs text-slate-400">
                        {edge.relationships.map((item) => RELATIONSHIP_LABELS[item]).join(" + ")}
                      </span>
                      <DecisionBadge decision={edge.decision} />
                    </button>
                  </li>
                );
              })}
            </ol>
          </Section>

          <Section title="How the score was calculated">
            <RiskFactorList
              factors={state.data.risk_factors}
              score={state.data.risk_score}
              rawScore={state.data.raw_score}
            />
          </Section>
        </>
      )}
    </div>
  );
}