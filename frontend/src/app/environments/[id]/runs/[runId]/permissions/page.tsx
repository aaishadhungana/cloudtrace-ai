"use client";

import Link from "next/link";
import { useParams } from "next/navigation";
import { useMemo, useState } from "react";
import { useCallback } from "react";
import { SeverityBadge } from "@/components/analysis/SeverityBadge";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { inputClass } from "@/components/ui/styles";
import type { Effect } from "@/lib/analysis-types";
import { listPermissions } from "@/lib/insight-api";
import type { PermissionEntry } from "@/lib/insight-types";
import { formatValue } from "@/lib/labels";
import { useApiResource } from "@/lib/use-api-resource";

const SOURCE_LABELS: Record<PermissionEntry["source_kind"], string> = {
  policy: "Identity policy",
  trust: "Trust policy",
  resource_policy: "Resource policy",
};

function EffectBadge({ effect }: { effect: Effect }) {
  const style =
    effect === "allow" ? "bg-amber-500/15 text-amber-300" : "bg-emerald-500/15 text-emerald-300";
  return (
    <span className={`rounded-full px-2.5 py-0.5 text-xs font-medium capitalize ${style}`}>
      {effect}
    </span>
  );
}

function matchesSearch(entry: PermissionEntry, search: string): boolean {
  if (!search) {
    return true;
  }
  const haystack = [entry.source_name, entry.sid ?? "", ...entry.actions, ...entry.targets]
    .join(" ")
    .toLowerCase();
  return haystack.includes(search.toLowerCase());
}

export default function PermissionsPage() {
  const { id, runId } = useParams<{ id: string; runId: string }>();
  const base = `/environments/${id}/runs/${runId}`;
  const loadPermissions = useCallback(
    (signal: AbortSignal) => listPermissions(id, runId, signal),
    [id, runId],
  );
  const { state } = useApiResource(loadPermissions);
  const [effect, setEffect] = useState<Effect | "">("");
  const [kind, setKind] = useState<PermissionEntry["source_kind"] | "">("");
  const [search, setSearch] = useState("");

  const visible = useMemo(() => {
    if (state.kind !== "ready") {
      return [];
    }
    return state.data.items.filter(
      (entry) =>
        (!effect || entry.effect === effect) &&
        (!kind || entry.source_kind === kind) &&
        matchesSearch(entry, search.trim()),
    );
  }, [state, effect, kind, search]);

  return (
    <div className="space-y-4">
      <p className="text-sm text-slate-400">
        Every policy statement in the import, with the identities that hold it and the findings
        that cite it as evidence. Conditions are shown as imported and are never evaluated.
      </p>
      <div className="flex flex-wrap items-end gap-4">
        <div className="space-y-1">
          <label htmlFor="effect-filter" className="block text-xs text-slate-500">
            Effect
          </label>
          <select
            id="effect-filter"
            className={inputClass}
            value={effect}
            onChange={(event) => setEffect(event.target.value as Effect | "")}
          >
            <option value="">All</option>
            <option value="allow">Allow</option>
            <option value="deny">Deny</option>
          </select>
        </div>
        <div className="space-y-1">
          <label htmlFor="kind-filter" className="block text-xs text-slate-500">
            Source
          </label>
          <select
            id="kind-filter"
            className={inputClass}
            value={kind}
            onChange={(event) => setKind(event.target.value as PermissionEntry["source_kind"] | "")}
          >
            <option value="">All</option>
            <option value="policy">Identity policy</option>
            <option value="trust">Trust policy</option>
            <option value="resource_policy">Resource policy</option>
          </select>
        </div>
        <div className="space-y-1">
          <label htmlFor="permission-search" className="block text-xs text-slate-500">
            Search
          </label>
          <input
            id="permission-search"
            className={inputClass}
            placeholder="policy, action or resource"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        </div>
      </div>

      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && (
        <>
          <p className="text-xs text-slate-500">
            Showing {visible.length} of {state.data.items.length}
            {state.data.total > state.data.items.length
              ? ` loaded statements (${state.data.total} in total)`
              : " statements"}
          </p>
          {visible.length === 0 && (
            <div className="rounded-lg border border-dashed border-line p-8 text-center">
              <p className="text-sm text-slate-400">No statements match.</p>
            </div>
          )}
          <ul className="space-y-3">
            {visible.map((entry) => (
              <li key={entry.key} className="rounded-lg border border-line bg-panel p-4">
                <div className="flex flex-wrap items-center gap-3">
                  <EffectBadge effect={entry.effect} />
                  <span className="text-sm font-medium text-white">{entry.source_name}</span>
                  <span className="text-xs text-slate-500">
                    {SOURCE_LABELS[entry.source_kind]}
                    {entry.sid ? ` · ${entry.sid}` : ""}
                  </span>
                </div>
                <dl className="mt-3 grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1 text-xs">
                  <dt className="text-slate-500">Actions</dt>
                  <dd className="break-all font-mono text-slate-300">{entry.actions.join(", ")}</dd>
                  <dt className="text-slate-500 capitalize">{entry.target_label}</dt>
                  <dd className="break-all font-mono text-slate-300">{entry.targets.join(", ")}</dd>
                  <dt className="text-slate-500">Conditions</dt>
                  <dd className="break-all font-mono text-slate-300">
                    {Object.keys(entry.conditions).length === 0
                      ? "none"
                      : formatValue(entry.conditions)}
                  </dd>
                </dl>
                {entry.related_identities.length > 0 && (
                  <p className="mt-3 text-xs text-slate-400">
                    Held by:{" "}
                    {entry.related_identities.map((identity, index) => (
                      <span key={identity.id}>
                        {index > 0 && ", "}
                        <Link
                          href={`${base}/identities/${identity.id}`}
                          className="text-accent hover:underline"
                        >
                          {identity.name}
                        </Link>
                      </span>
                    ))}
                  </p>
                )}
                {entry.related_findings.length > 0 && (
                  <ul className="mt-2 space-y-1">
                    {entry.related_findings.map((finding) => (
                      <li key={finding.id} className="flex flex-wrap items-center gap-2 text-xs">
                        <SeverityBadge severity={finding.severity} />
                        <Link
                          href={`${base}/findings/${finding.id}`}
                          className="text-slate-200 hover:text-accent"
                        >
                          {finding.title}
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  );
}