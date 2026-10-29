"use client";

import { useEffect, useState } from "react";
import { CheckCircle2, CircleAlert, Loader2 } from "lucide-react";
import { getHealth } from "@/lib/api";
import type { HealthResponse } from "@/lib/types";

type StatusState =
  | { kind: "loading" }
  | { kind: "ready"; health: HealthResponse }
  | { kind: "error"; message: string };

export function BackendStatus() {
  const [state, setState] = useState<StatusState>({ kind: "loading" });

  useEffect(() => {
    const controller = new AbortController();
    getHealth(controller.signal)
      .then((health) => setState({ kind: "ready", health }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setState({
          kind: "error",
          message: error instanceof Error ? error.message : "Unknown error",
        });
      });
    return () => controller.abort();
  }, []);

  return (
    <section className="rounded-lg border border-line bg-panel p-5">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">
        Backend status
      </h2>
      {state.kind === "loading" && (
        <p className="flex items-center gap-2 text-sm text-slate-300">
          <Loader2 className="h-4 w-4 animate-spin" aria-hidden />
          Checking backend
        </p>
      )}
      {state.kind === "ready" && (
        <p className="flex items-center gap-2 text-sm text-emerald-400">
          <CheckCircle2 className="h-4 w-4" aria-hidden />
          API {state.health.status}, database {state.health.database}, version{" "}
          {state.health.version}
        </p>
      )}
      {state.kind === "error" && (
        <p className="flex items-center gap-2 text-sm text-red-400">
          <CircleAlert className="h-4 w-4" aria-hidden />
          Backend unreachable: {state.message}
        </p>
      )}
    </section>
  );
}