import { ApiError } from "@/lib/api";
import type { ImportIssue } from "@/lib/types";

export interface ErrorDescription {
  message: string;
  issues: ImportIssue[];
}

export function describeError(error: unknown): ErrorDescription {
  if (error instanceof ApiError) {
    return { message: error.message, issues: error.issues };
  }
  if (error instanceof Error) {
    return { message: error.message, issues: [] };
  }
  return { message: "Something went wrong", issues: [] };
}