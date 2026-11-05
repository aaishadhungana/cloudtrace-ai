"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useCallback } from "react";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { listIdentities } from "@/lib/analysis-api";
import { IDENTITY_TYPE_LABELS } from "@/lib/labels";
import { useApiResource } from "@/lib/use-api-resource";

export default function IdentitiesPage() {
  const { id, runId } = useParams<{ id: string; runId: string }>();
  const loadIdentities = useCallback(
    (signal: AbortSignal) => listIdentities(id, runId, signal),
    [id, runId],
  );
  const { state } = useApiResource(loadIdentities);

  if (state.kind === "loading") {
    return <Spinner />;
  }
  if (state.kind === "error") {
    return <ErrorBanner error={state.error} />;
  }

  return (
    <div className="overflow-x-auto rounded-lg border border-line">
      <table className="w-full text-left text-sm">
        <thead className="bg-panel text-xs uppercase tracking-wide text-slate-500">
          <tr>
            <th className="px-4 py-2 font-medium">Identity</th>
            <th className="px-4 py-2 font-medium">Type</th>
            <th className="px-4 py-2 font-medium">Policies</th>
            <th className="px-4 py-2 font-medium">Risk</th>
            <th className="px-4 py-2 font-medium">Findings</th>
            <th className="px-4 py-2 font-medium">Reaches</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-line">
          {state.data.map((identity) => (
            <tr key={identity.id} className="hover:bg-white/5">
              <td className="px-4 py-3">
                <Link
                  href={`/environments/${id}/runs/${runId}/identities/${identity.id}`}
                  className="text-slate-100 hover:text-accent"
                >
                  {identity.name}
                </Link>
                {identity.account_id && (
                  <p className="font-mono text-xs text-slate-500">{identity.account_id}</p>
                )}
              </td>
              <td className="px-4 py-3 text-slate-300">
                {IDENTITY_TYPE_LABELS[identity.identity_type]}
              </td>
              <td className="px-4 py-3 text-xs text-slate-400">
                {identity.policy_names.length > 0 ? identity.policy_names.join(", ") : "none"}
              </td>
              <td className="px-4 py-3">
                {identity.risk_level ? (
                  <SeverityBadge severity={identity.risk_level} />
                ) : (
                  <span className="text-xs text-slate-500">No findings</span>
                )}
              </td>
              <td className="px-4 py-3 font-mono text-slate-300">{identity.finding_count}</td>
              <td className="px-4 py-3 text-xs text-slate-400">
                {identity.reachable_target_count} targets, {identity.sensitive_target_count}{" "}
                sensitive
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}