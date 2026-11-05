"use client";

import { useParams } from "next/navigation";
import { useCallback, useState } from "react";
import { FindingsTable } from "@/components/analysis/FindingsTable";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { inputClass } from "@/components/ui/styles";
import { listFindings, listRules } from "@/lib/analysis-api";
import type { FindingSort, Severity } from "@/lib/analysis-types";
import { SEVERITY_ORDER } from "@/lib/labels";
import { useApiResource } from "@/lib/use-api-resource";

export default function FindingsPage() {
  const { id, runId } = useParams<{ id: string; runId: string }>();
  const [severity, setSeverity] = useState<Severity | "">("");
  const [ruleId, setRuleId] = useState("");
  const [sort, setSort] = useState<FindingSort>("score_desc");

  const loadFindings = useCallback(
    (signal: AbortSignal) =>
      listFindings(
        id,
        runId,
        { severity: severity || undefined, ruleId: ruleId || undefined, sort },
        signal,
      ),
    [id, runId, severity, ruleId, sort],
  );
  const { state } = useApiResource(loadFindings);
  const { state: rules } = useApiResource(listRules);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-end gap-4">
        <div className="space-y-1">
          <label htmlFor="severity-filter" className="block text-xs text-slate-500">
            Severity
          </label>
          <select
            id="severity-filter"
            className={inputClass}
            value={severity}
            onChange={(event) => setSeverity(event.target.value as Severity | "")}
          >
            <option value="">All</option>
            {SEVERITY_ORDER.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </div>
        <div className="space-y-1">
          <label htmlFor="rule-filter" className="block text-xs text-slate-500">
            Rule
          </label>
          <select
            id="rule-filter"
            className={inputClass}
            value={ruleId}
            onChange={(event) => setRuleId(event.target.value)}
          >
            <option value="">All</option>
            {rules.kind === "ready" &&
              rules.data.map((rule) => (
                <option key={rule.rule_id} value={rule.rule_id}>
                  {rule.rule_id} {rule.title}
                </option>
              ))}
          </select>
        </div>
        <div className="space-y-1">
          <label htmlFor="sort-select" className="block text-xs text-slate-500">
            Sort
          </label>
          <select
            id="sort-select"
            className={inputClass}
            value={sort}
            onChange={(event) => setSort(event.target.value as FindingSort)}
          >
            <option value="score_desc">Highest score</option>
            <option value="score_asc">Lowest score</option>
            <option value="rule">Rule</option>
          </select>
        </div>
      </div>
      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && (
        <>
          <p className="text-xs text-slate-500">
            Showing {state.data.items.length} of {state.data.total}
          </p>
          <FindingsTable
            findings={state.data.items}
            basePath={`/environments/${id}/runs/${runId}`}
          />
        </>
      )}
    </div>
  );
}