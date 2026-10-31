"use client";

import Link from "next/link";
import { BackendStatus } from "@/components/BackendStatus";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { cardClass } from "@/components/ui/styles";
import { listEnvironments } from "@/lib/api";
import { useApiResource } from "@/lib/use-api-resource";

export default function OverviewPage() {
  const { state } = useApiResource(listEnvironments);

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight text-white">Overview</h1>
        <p className="mt-1 text-sm text-slate-400">
          Cloud identity security and attack-path analysis.
        </p>
      </header>
      <BackendStatus />
      <section className={cardClass}>
        <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">
          Environments
        </h2>
        {state.kind === "loading" && <Spinner />}
        {state.kind === "error" && <ErrorBanner error={state.error} />}
        {state.kind === "ready" && state.data.length === 0 && (
          <p className="text-sm text-slate-400">
            No environments yet.{" "}
            <Link href="/environments" className="text-accent hover:underline">
              Create your first environment
            </Link>
            .
          </p>
        )}
        {state.kind === "ready" && state.data.length > 0 && (
          <p className="text-sm text-slate-300">
            <span className="text-2xl font-semibold text-white">{state.data.length}</span>{" "}
            <Link href="/environments" className="text-accent hover:underline">
              {state.data.length === 1 ? "environment" : "environments"}
            </Link>
          </p>
        )}
      </section>
    </div>
  );
}