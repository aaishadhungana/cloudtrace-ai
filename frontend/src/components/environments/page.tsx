"use client";

import Link from "next/link";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { cardClass } from "@/components/ui/styles";
import { CreateEnvironmentForm } from "@/components/environments/CreateEnvironmentForm";
import { listEnvironments } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useApiResource } from "@/lib/use-api-resource";

export default function EnvironmentsPage() {
  const { state, reload } = useApiResource(listEnvironments);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-white">Environments</h1>
        <p className="mt-1 text-sm text-slate-400">
          Each environment holds imported cloud configurations.
        </p>
      </header>
      <CreateEnvironmentForm onCreated={reload} />
      <section className="space-y-3">
        {state.kind === "loading" && <Spinner />}
        {state.kind === "error" && <ErrorBanner error={state.error} />}
        {state.kind === "ready" && state.data.length === 0 && (
          <div className="rounded-lg border border-dashed border-line p-8 text-center">
            <p className="text-sm text-slate-400">No environments yet. Create one above.</p>
          </div>
        )}
        {state.kind === "ready" &&
          state.data.map((environment) => (
            <Link
              key={environment.id}
              href={`/environments/${environment.id}`}
              className={`${cardClass} block transition-colors hover:border-accent/50`}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <p className="truncate font-medium text-white">{environment.name}</p>
                  {environment.description && (
                    <p className="mt-1 line-clamp-2 text-sm text-slate-400">
                      {environment.description}
                    </p>
                  )}
                </div>
                <div className="shrink-0 text-right text-xs text-slate-500">
                  <p className="uppercase">{environment.cloud_provider}</p>
                  <p>{formatDateTime(environment.created_at)}</p>
                </div>
              </div>
            </Link>
          ))}
      </section>
    </div>
  );
}