import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AiAnalysisView } from "@/components/ai/AiAnalysisView";
import { ApiError } from "@/lib/api";
import type { AIAnalysis, AIStatus } from "@/lib/ai-types";
import type { ResourceState } from "@/lib/use-api-resource";

afterEach(cleanup);

const available: ResourceState<AIStatus> = {
  kind: "ready",
  data: { available: true, model: "test-model", reason: null },
};

const unavailable: ResourceState<AIStatus> = {
  kind: "ready",
  data: { available: false, model: null, reason: "Gemini is not configured." },
};

const analysis: AIAnalysis<string> = {
  subject_type: "finding",
  subject_id: "1",
  model: "test-model",
  generated_at: "2026-11-10T10:00:00Z",
  cached: false,
  notice: "AI-generated explanation. It is not verified evidence.",
  content: "Generated text",
};

function renderView(overrides: Partial<Parameters<typeof AiAnalysisView<string>>[0]> = {}) {
  const onGenerate = vi.fn();
  render(
    <AiAnalysisView<string>
      status={available}
      stored={{ kind: "ready", data: null }}
      generating={false}
      error={null}
      onGenerate={onGenerate}
      renderContent={(content) => <p>{content}</p>}
      {...overrides}
    />,
  );
  return onGenerate;
}

describe("AiAnalysisView", () => {
  it("says AI is unavailable and shows no generate button when not configured", () => {
    renderView({ status: unavailable });
    expect(screen.getByText(/AI analysis is unavailable/)).toBeTruthy();
    expect(screen.getByText(/do not depend on it/)).toBeTruthy();
    expect(screen.queryByRole("button")).toBeNull();
  });

  it("offers to generate when nothing is stored", () => {
    const onGenerate = renderView();
    fireEvent.click(screen.getByRole("button", { name: "Generate AI analysis" }));
    expect(onGenerate).toHaveBeenCalledWith(false);
  });

  it("shows stored analysis with its AI label and regenerates on request", () => {
    const onGenerate = renderView({ stored: { kind: "ready", data: analysis } });
    expect(screen.getByText("Generated text")).toBeTruthy();
    expect(screen.getAllByText(/AI-generated/).length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Regenerate" }));
    expect(onGenerate).toHaveBeenCalledWith(true);
  });

  it("shows an error without inventing content when generation fails", () => {
    renderView({ error: new ApiError("The AI provider quota or rate limit was reached.", 429) });
    expect(screen.getByRole("alert").textContent).toContain("quota or rate limit");
    expect(screen.getByText(/unaffected/)).toBeTruthy();
    expect(screen.queryByText("Generated text")).toBeNull();
  });

  it("shows only a spinner while loading", () => {
    renderView({ status: { kind: "loading" } });
    expect(screen.queryByRole("button")).toBeNull();
    expect(screen.getByText("Loading")).toBeTruthy();
  });
});