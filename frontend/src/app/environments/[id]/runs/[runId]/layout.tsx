"use client";

import Link from "next/link";
import { useParams, usePathname } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { useCallback } from "react";
import type { ReactNode } from "react";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { getRun } from "@/lib/analysis-api";
import { formatDateTime } from "@/lib/format";
import { RunProvider } from "@/lib/run-context";
import { useApiResource } from "@/lib/use-api-resource";

export default function RunLayout({ children }: { children: ReactNode }) {
  const { id, runId } = useParams<{ id: string; runId: string }>();
  const pathname = usePathname();
  const loadRun = useCallback((signal: AbortSignal) => getRun(id, runId, signal), [id, runId]);
  const { state } = useApiResource(loadRun);
  const base = `/environments/${id}/runs/${runId}`;
  const tabs = [
    { label: "Overview", href: base },
    { label: "Findings", href: `${base}/findings` },
    { label: "Attack paths", href: `${base}/attack-paths` },
    { label: "Identities", href: `${base}/identities` },
  ];

  return (
    <div className="mx-auto max-w-5xl space-y-6">
      <Link
        href={`/environments/${id}`}
        className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden />
        Environment
      </Link>
      {state.kind === "loading" && <Spinner />}
      {state.kind === "error" && <ErrorBanner error={state.error} />}
      {state.kind === "ready" && (
        <>
          <header>
            <h1 className="text-2xl font-semibold tracking-tight text-white">
              Analysis run
            </h1>
            <p className="mt-1 text-xs text-slate-500">
              {formatDateTime(state.data.started_at)} · <span className="capitalize">{state.data.status}</span>{" "}
              · engine {state.data.analysis_version}
            </p>
          </header>
          <nav className="flex gap-1 border-b border-line" aria-label="Run sections">
            {tabs.map((tab) => {
              const active = tab.href === base ? pathname === base : pathname.startsWith(tab.href);
              return (
                <Link
                  key={tab.href}
                  href={tab.href}
                  aria-current={active ? "page" : undefined}
                  className={`-mb-px border-b-2 px-4 py-2 text-sm transition-colors ${
                    active
                      ? "border-accent text-accent"
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  {tab.label}
                </Link>
              );
            })}
          </nav>
          <RunProvider value={state.data}>{children}</RunProvider>
        </>
      )}
    </div>
  );
}