"use client";

import { useCallback, useEffect, useState } from "react";

export type ResourceState<T> =
  | { kind: "loading" }
  | { kind: "ready"; data: T }
  | { kind: "error"; error: unknown };

export function useApiResource<T>(loader: (signal: AbortSignal) => Promise<T>) {
  const [state, setState] = useState<ResourceState<T>>({ kind: "loading" });
  const [reloadCount, setReloadCount] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    loader(controller.signal)
      .then((data) => setState({ kind: "ready", data }))
      .catch((error: unknown) => {
        if (controller.signal.aborted) {
          return;
        }
        setState({ kind: "error", error });
      });
    return () => controller.abort();
  }, [loader, reloadCount]);

  const reload = useCallback(() => setReloadCount((count) => count + 1), []);

  return { state, reload };
}