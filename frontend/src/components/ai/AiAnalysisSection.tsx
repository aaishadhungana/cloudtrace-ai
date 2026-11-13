"use client";

import { useCallback, useState } from "react";
import type { ReactNode } from "react";
import { AiAnalysisView } from "@/components/ai/AiAnalysisView";
import { getAiStatus } from "@/lib/ai-api";
import type { AIAnalysis } from "@/lib/ai-types";
import { useApiResource } from "@/lib/use-api-resource";
import type { ResourceState } from "@/lib/use-api-resource";

interface AiAnalysisSectionProps<C> {
  environmentId: string;
  runId: string;
  load: (signal: AbortSignal) => Promise<AIAnalysis<C> | null>;
  generate: (refresh: boolean) => Promise<AIAnalysis<C>>;
  renderContent: (content: C) => ReactNode;
}

export function AiAnalysisSection<C>({
  environmentId,
  runId,
  load,
  generate,
  renderContent,
}: AiAnalysisSectionProps<C>) {
  const loadStatus = useCallback(
    (signal: AbortSignal) => getAiStatus(environmentId, runId, signal),
    [environmentId, runId],
  );
  const { state: status } = useApiResource(loadStatus);
  const { state: stored } = useApiResource(load);
  const [generated, setGenerated] = useState<AIAnalysis<C> | null>(null);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function handleGenerate(refresh: boolean) {
    setGenerating(true);
    setError(null);
    try {
      setGenerated(await generate(refresh));
    } catch (caught) {
      setError(caught);
    } finally {
      setGenerating(false);
    }
  }

  const effective: ResourceState<AIAnalysis<C> | null> =
    generated !== null ? { kind: "ready", data: generated } : stored;

  return (
    <AiAnalysisView
      status={status}
      stored={effective}
      generating={generating}
      error={error}
      onGenerate={handleGenerate}
      renderContent={renderContent}
    />
  );
}