"use client";

import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { ArrowLeft, Trash2 } from "lucide-react";
import { useCallback, useState } from "react";
import { ImportHistory } from "@/components/environments/ImportHistory";
import { ImportPanel } from "@/components/environments/ImportPanel";
import { Button } from "@/components/ui/Button";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import { deleteEnvironment, getEnvironment, listImports } from "@/lib/api";
import { formatDateTime } from "@/lib/format";
import { useApiResource } from "@/lib/use-api-resource";

export default function EnvironmentDetailPage() {
  const { id } = useParams<{ id: string }>();
  const router = useRouter();
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<unknown>(null);

  const loadEnvironment = useCallback((signal: AbortSignal) => getEnvironment(id, signal), [id]);
  const loadImports = useCallback((signal: AbortSignal) => listImports(id, signal), [id]);
  const { state: environment } = useApiResource(loadEnvironment);
  const { state: imports, reload: reloadImports } = useApiResource(loadImports);

  async function handleDelete(name: string) {
    const confirmed = window.confirm(`Delete "${name}" and all of its imports? This cannot be undone.`);
    if (!confirmed) {
      return;
    }
    setDeleting(true);
    setDeleteError(null);
    try {
      await deleteEnvironment(id);
      router.push("/environments");
    } catch (caught) {
      setDeleteError(caught);
      setDeleting(false);
    }
  }

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <Link
        href="/environments"
        className="inline-flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200"
      >
        <ArrowLeft className="h-4 w-4" aria-hidden />
        Environments
      </Link>

      {environment.kind === "loading" && <Spinner />}
      {environment.kind === "error" && <ErrorBanner error={environment.error} />}
      {environment.kind === "ready" && (
        <>
          <header className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <h1 className="truncate text-2xl font-semibold tracking-tight text-white">
                {environment.data.name}
              </h1>
              {environment.data.description && (
                <p className="mt-1 text-sm text-slate-400">{environment.data.description}</p>
              )}
              <p className="mt-2 text-xs text-slate-500">
                {environment.data.cloud_provider.toUpperCase()} · created{" "}
                {formatDateTime(environment.data.created_at)}
              </p>
            </div>
            <Button
              variant="danger"
              loading={deleting}
              onClick={() => handleDelete(environment.data.name)}
            >
              <Trash2 className="h-4 w-4" aria-hidden />
              Delete
            </Button>
          </header>
          {deleteError !== null && <ErrorBanner error={deleteError} />}
          <ImportPanel environmentId={id} onImported={reloadImports} />
          <ImportHistory state={imports} />
        </>
      )}
    </div>
  );
}