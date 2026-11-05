"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { useCallback } from "react";
import { EvidenceList } from "@/components/analysis/EvidenceList";
import { RiskFactorList } from "@/components/analysis/RiskFactorList";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Section } from "@/components/ui/Section";
import { Spinner } from "@/components/ui/Spinner";
import { getFinding } from "@/lib/analysis-api";
import { useApiResource } from "@/lib/use-api-resource";

export default function FindingDetailPage() {
  const { id, runId, findingId } = useParams<{ id: string; runId: string; findingId: string }>();
  const base = `/environments/${id}/runs/${runId}`;
  const loadFinding = useCallback(
    (signal: AbortSignal) => getFinding(id, runId, findingId, signal),
    [id, runId, findingId],
  );
  const { state } = useApiResource(loadFinding);

  return (
    <div className="space-y-6">
      <Link
        href={`${base}/findings`}
        className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden />
        Findings
      </Link>
      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && (
        <>
          <header className="space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <SeverityBadge severity={state.data.severity} />
              <span className="font-mono text-sm text-slate-300">
                Risk score {state.data.risk_score}/100
              </span>
              <span className="font-mono text-xs text-slate-500">{state.data.rule_id}</span>
              <span className="text-xs capitalize text-slate-500">{state.data.status}</span>
            </div>
            <h1 className="text-xl font-semibold tracking-tight text-white">{state.data.title}</h1>
            <p className="text-sm text-slate-400">
              {state.data.identity_id && (
                <>
                  Identity:{" "}
                  <Link
                    href={`${base}/identities/${state.data.identity_id}`}
                    className="text-accent hover:underline"
                  >
                    {state.data.identity_name}
                  </Link>{" "}
                </>
              )}
              {state.data.resource_name && (
                <>
                  Resource:{" "}
                  <span className="text-slate-200" title={state.data.resource_arn ?? undefined}>
                    {state.data.resource_name}
                  </span>
                </>
              )}
            </p>
            <p className="text-xs text-slate-500">
              Deterministic analysis result. A score ranks configuration risk and does not confirm
              that the finding is exploitable.
            </p>
          </header>
          <Section title="What was detected">
            <p className="text-sm leading-relaxed text-slate-300">{state.data.explanation}</p>
          </Section>
          <Section title="Recommended remediation">
            <p className="text-sm leading-relaxed text-slate-300">{state.data.remediation}</p>
          </Section>
          <Section title="How the score was calculated">
            <RiskFactorList
              factors={state.data.risk_factors}
              score={state.data.risk_score}
              rawScore={state.data.raw_score}
            />
          </Section>
          <Section title="Evidence">
            <EvidenceList items={state.data.evidence} />
          </Section>
        </>
      )}
    </div>
  );
}