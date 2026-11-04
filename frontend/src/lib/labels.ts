import type { Decision, IdentityType, RelationshipType, Severity } from "@/lib/analysis-types";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const RELATIONSHIP_LABELS: Record<RelationshipType, string> = {
  can_assume: "Assume role",
  can_read: "Read",
  can_write: "Write",
  can_modify_policy: "Modify IAM policy",
  can_pass_role: "Pass role",
  accessible_to_principal: "Accessible to principal",
};

export const DECISION_LABELS: Record<Decision, string> = {
  allowed: "Allowed",
  conditional: "Conditional",
  explicitly_denied: "Explicitly denied",
  not_allowed: "Not allowed",
};

export const IDENTITY_TYPE_LABELS: Record<IdentityType, string> = {
  iam_user: "IAM user",
  iam_role: "IAM role",
  service: "Service",
  external_principal: "External principal",
};

export function humanize(value: string): string {
  const spaced = value.replace(/_/g, " ");
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function formatValue(value: unknown): string {
  if (value === null || value === undefined) {
    return "none";
  }
  if (Array.isArray(value) && value.every((item) => typeof item === "string")) {
    return value.length === 0 ? "none" : value.join(", ");
  }
  if (typeof value === "object") {
    return JSON.stringify(value);
  }
  return String(value);
}