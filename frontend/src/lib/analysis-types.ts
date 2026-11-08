export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type RunStatus = "pending" | "running" | "completed" | "failed";
export type Decision = "allowed" | "conditional" | "explicitly_denied" | "not_allowed";
export type Effect = "allow" | "deny";
export type FindingStatus = "open" | "acknowledged" | "resolved";
export type FindingSort = "score_desc" | "score_asc" | "rule";
export type IdentityType = "iam_user" | "iam_role" | "service" | "external_principal";
export type RelationshipType =
  | "can_assume"
  | "can_read"
  | "can_write"
  | "can_modify_policy"
  | "can_pass_role"
  | "accessible_to_principal";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface AnalysisRun {
  id: string;
  environment_id: string;
  import_id: string;
  status: RunStatus;
  analysis_version: string;
  started_at: string;
  completed_at: string | null;
  finding_count: number;
  attack_path_count: number;
  paths_incomplete: boolean;
  severity_counts: SeverityCounts;
}

export interface AnalysisRunDetail extends AnalysisRun {
  limitations: string[];
  import_source: string;
  import_created_at: string;
}

export interface Rule {
  rule_id: string;
  title: string;
  description: string;
  finding_type: string;
}

export interface RiskFactor {
  name: string;
  points: number;
  detail: string;
}

export interface FindingSummary {
  id: string;
  analysis_run_id: string;
  rule_id: string;
  finding_type: string;
  title: string;
  severity: Severity;
  risk_score: number;
  status: FindingStatus;
  identity_id: string | null;
  identity_name: string | null;
  resource_id: string | null;
  resource_name: string | null;
  created_at: string;
}

export interface FindingDetail extends FindingSummary {
  identity_arn: string | null;
  resource_arn: string | null;
  explanation: string;
  remediation: string;
  raw_score: number;
  risk_factors: RiskFactor[];
  evidence: Record<string, unknown>[];
}

export interface FindingList {
  total: number;
  items: FindingSummary[];
}

export interface FindingQuery {
  severity?: Severity;
  ruleId?: string;
  sort?: FindingSort;
}

export interface IdentitySummary {
  id: string;
  arn: string;
  name: string;
  identity_type: IdentityType;
  account_id: string | null;
  policy_names: string[];
  finding_count: number;
  max_risk_score: number | null;
  risk_level: Severity | null;
  reachable_target_count: number;
  sensitive_target_count: number;
}

export interface PolicyView {
  id: string;
  name: string;
  statements: Record<string, unknown>[];
}

export interface AccessEntry {
  target_kind: string;
  target_id: string;
  target_arn: string;
  target_name: string;
  is_sensitive: boolean;
  relationship_type: RelationshipType;
  effect: Effect;
  decision: Decision;
  actions: string[];
  notes: string[];
  statements: Record<string, unknown>[];
}

export interface IdentityDetail extends IdentitySummary {
  policies: PolicyView[];
  trust_policy: { statements: Record<string, unknown>[] } | null;
  access: AccessEntry[];
  findings: FindingSummary[];
}