"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { useCallback } from "react";
import { DecisionBadge } from "@/components/analysis/DecisionBadge";
import { EvidenceList } from "@/components/analysis/EvidenceList";
import { FindingsTable } from "@/components/analysis/FindingsTable";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import { RelatedAttackPaths } from "@/components/attack-paths/RelatedAttackPaths";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Section } from "@/components/ui/Section";
import { Spinner } from "@/components/ui/Spinner";
import { getIdentity } from "@/lib/analysis-api";
import { IDENTITY_TYPE_LABELS, RELATIONSHIP_LABELS } from "@/lib/labels";
import { useApiResource } from "@/lib/use-api-resource";

export default function IdentityDetailPage() {
  const { id, runId, identityId } = useParams<{ id: string; runId: string; identityId: string }>();
  const base = `/environments/${id}/runs/${runId}`;
  const loadIdentity = useCallback(
    (signal: AbortSignal) => getIdentity(id, runId, identityId, signal),
    [id, runId, identityId],
  );
  const { state } = useApiResource(loadIdentity);

  return (
    <div className="space-y-6">
      <Link
        href={`${base}/identities`}
        className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden />
        Identities
      </Link>
      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && (
        <>
          <header className="space-y-2">
            <div className="flex flex-wrap items-center gap-3">
              <h1 className="text-xl font-semibold tracking-tight text-white">{state.data.name}</h1>
              <span className="text-sm text-slate-400">
                {IDENTITY_TYPE_LABELS[state.data.identity_type]}
              </span>
              {state.data.risk_level ? (
                <SeverityBadge severity={state.data.risk_level} />
              ) : (
                <span className="text-xs text-slate-500">No findings</span>
              )}
            </div>
            <p className="break-all font-mono text-xs text-slate-500">{state.data.arn}</p>
          </header>

          <Section title="Findings">
            <FindingsTable findings={state.data.findings} basePath={base} />
          </Section>

          <Section title="Attack paths from this identity">
            <RelatedAttackPaths
              environmentId={id}
              runId={runId}
              startIdentityId={identityId}
            />
          </Section>

          <Section title="Effective access">
            {state.data.access.length === 0 ? (
              <p className="text-sm text-slate-500">
                No effective access was established for this identity.
              </p>
            ) : (
              <ul className="space-y-3">
                {state.data.access.map((entry) => (
                  <li
                    key={`${entry.target_id}-${entry.relationship_type}`}
                    className="rounded-md border border-line bg-ink p-3"
                  >
                    <div className="flex flex-wrap items-center gap-3">
                      <span className="text-sm text-slate-100">{entry.target_name}</span>
                      <span className="text-xs text-slate-400">
                        {RELATIONSHIP_LABELS[entry.relationship_type]}
                      </span>
                      <DecisionBadge decision={entry.decision} />
                      {entry.is_sensitive && (
                        <span className="rounded-full bg-red-500/15 px-2 py-0.5 text-xs text-red-300">
                          Sensitive
                        </span>
                      )}
                    </div>
                    <p className="mt-1 font-mono text-xs text-slate-500">
                      {entry.actions.join(", ")}
                    </p>
                    {entry.notes.map((note) => (
                      <p key={note} className="mt-1 text-xs text-sky-300">
                        {note}
                      </p>
                    ))}
                    <details className="mt-2">
                      <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-200">
                        Supporting statements ({entry.statements.length})
                      </summary>
                      <div className="mt-2">
                        <EvidenceList items={entry.statements} />
                      </div>
                    </details>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title="Attached policies">
            {state.data.policies.length === 0 ? (
              <p className="text-sm text-slate-500">No policies attached.</p>
            ) : (
              state.data.policies.map((policy) => (
                <div key={policy.id} className="space-y-2">
                  <p className="text-sm font-medium text-slate-200">{policy.name}</p>
                  <EvidenceList
                    items={policy.statements.map((statement) => ({
                      kind: "policy_statement",
                      ...statement,
                    }))}
                  />
                </div>
              ))
            )}
          </Section>

          {state.data.trust_policy && (
            <Section title="Trust policy">
              <EvidenceList
                items={state.data.trust_policy.statements.map((statement) => ({
                  kind: "trust_statement",
                  ...statement,
                }))}
              />
            </Section>
          )}
        </>
      )}
    </div>
  );
}