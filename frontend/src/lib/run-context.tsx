"use client";

import { createContext, useContext } from "react";
import type { AnalysisRunDetail } from "@/lib/analysis-types";

const RunContext = createContext<AnalysisRunDetail | null>(null);

export const RunProvider = RunContext.Provider;

export function useRun(): AnalysisRunDetail {
  const run = useContext(RunContext);
  if (run === null) {
    throw new Error("useRun must be used inside a run layout");
  }
  return run;
}