import { ImportCounts } from "@/components/environments/ImportCounts";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { cardClass } from "@/components/ui/styles";
import { formatDateTime } from "@/lib/format";
import type { ImportRecord } from "@/lib/types";
import type { ResourceState } from "@/lib/use-api-resource";

export function ImportHistory({ state }: { state: ResourceState<ImportRecord[]> }) {
  return (
    <section className="space-y-3">
      <h2 className="text-sm font-medium uppercase tracking-wide text-slate-400">
        Import history
      </h2>
      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && state.data.length === 0 && (
        <div className="rounded-lg border border-dashed border-line p-8 text-center">
          <p className="text-sm text-slate-400">No imports yet.</p>
        </div>
      )}
      {state.kind === "ready" &&
        state.data.map((record) => (
          <article key={record.id} className={`${cardClass} space-y-3`}>
            <div className="flex items-start justify-between gap-4">
              <div className="min-w-0">
                <p className="truncate font-medium text-white">{record.import_source}</p>
                <p className="text-xs text-slate-500">
                  {formatDateTime(record.created_at)} · schema {record.schema_version}
                </p>
              </div>
              <span className="rounded-full bg-emerald-500/10 px-2.5 py-0.5 text-xs font-medium text-emerald-300">
                {record.validation_status}
              </span>
            </div>
            <ImportCounts metadata={record.sanitized_metadata} />
          </article>
        ))}
    </section>
  );
}