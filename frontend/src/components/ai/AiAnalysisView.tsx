import { Sparkles } from "lucide-react";
import type { ReactNode } from "react";
import { Button } from "@/components/ui/Button";
import { ErrorBanner } from "@/components/ui/ErrorBanner";
import { Spinner } from "@/components/ui/Spinner";
import type { AIAnalysis, AIStatus } from "@/lib/ai-types";
import { formatDateTime } from "@/lib/format";
import type { ResourceState } from "@/lib/use-api-resource";

interface AiAnalysisViewProps<C> {
  status: ResourceState<AIStatus>;
  stored: ResourceState<AIAnalysis<C> | null>;
  generating: boolean;
  error: unknown;
  onGenerate: (refresh: boolean) => void;
  renderContent: (content: C) => ReactNode;
}

export function AiAnalysisView<C>({
  status,
  stored,
  generating,
  error,
  onGenerate,
  renderContent,
}: AiAnalysisViewProps<C>) {
  const analysis = stored.kind === "ready" ? stored.data : null;
  const loading = status.kind === "loading" || stored.kind === "loading";
  const canGenerate = status.kind === "ready" && status.data.available;
  const reason = status.kind === "ready" && !status.data.available ? status.data.reason : null;

  return (
    <section
      aria-label="AI-generated analysis"
      className="space-y-4 rounded-lg border border-violet-500/30 bg-violet-500/5 p-5"
    >
      <header className="flex items-center justify-between gap-3">
        <h2 className="flex items-center gap-2 text-sm font-medium uppercase tracking-wide text-violet-300">
          <Sparkles className="h-4 w-4" aria-hidden />
          AI analysis
        </h2>
        <span className="rounded-full bg-violet-500/20 px-2.5 py-0.5 text-xs font-medium text-violet-200">
          AI-generated
        </span>
      </header>

      {loading && <Spinner />}
      {status.kind === "error" && <ErrorBanner error={status.error} />}
      {stored.kind === "error" && <ErrorBanner error={stored.error} />}

      {analysis !== null && (
        <>
          <p className="text-xs text-slate-400">{analysis.notice}</p>
          <p className="text-xs text-slate-500">
            Model {analysis.model} · generated {formatDateTime(analysis.generated_at)}
          </p>
          {renderContent(analysis.content)}
        </>
      )}

      {!loading && analysis === null && reason !== null && (
        <p className="text-sm text-slate-300">
          AI analysis is unavailable: {reason} The findings, scores and attack paths on this page
          are deterministic and do not depend on it.
        </p>
      )}

      {!loading && analysis === null && canGenerate && (
        <p className="text-sm text-slate-400">
          No AI analysis has been generated for this yet. Generating one sends the finding data,
          without credentials, to the configured Gemini model.
        </p>
      )}

      {error !== null && (
        <div className="space-y-2">
          <ErrorBanner error={error} />
          <p className="text-xs text-slate-400">
            AI analysis is unavailable right now. Findings, scores and attack paths are
            unaffected.
          </p>
        </div>
      )}

      {canGenerate && !loading && (
        <Button
          variant={analysis === null ? "primary" : "secondary"}
          loading={generating}
          onClick={() => onGenerate(analysis !== null)}
        >
          {analysis === null ? "Generate AI analysis" : "Regenerate"}
        </Button>
      )}
    </section>
  );
}