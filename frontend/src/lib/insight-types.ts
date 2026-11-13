import type { AIAnalysis, SecuritySummaryContent } from "@/lib/ai-types";
import type { Effect, RunStatus, Severity, SeverityCounts } from "@/lib/analysis-types";
import type { PathClassification } from "@/lib/attack-path-types";

export interface DashboardRun {
  run_id: string;
  environment_id: string;
  environment_name: string;
  started_at: string;
  status: RunStatus;
  finding_count: number;
  attack_path_count: number;
}

export interface DashboardFinding {
  finding_id: string;
  run_id: string;
  environment_id: string;
  environment_name: string;
  rule_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
}

export interface Dashboard {
  environment_count: number;
  analyzed_environment_count: number;
  identity_count: number;
  sensitive_resource_count: number;
  open_finding_count: number;
  critical_high_finding_count: number;
  attack_path_count: number;
  recent_runs: DashboardRun[];
  top_findings: DashboardFinding[];
}

export type ComparisonStatus = "new" | "persisting" | "no_longer_detected" | "not_comparable";

export interface StatusCounts {
  new: number;
  persisting: number;
  no_longer_detected: number;
  not_comparable: number;
}

export interface RunSide {
  run_id: string;
  import_id: string;
  import_source: string;
  started_at: string;
  analysis_version: string;
  finding_count: number;
  high_risk_finding_count: number;
  attack_path_count: number;
  paths_incomplete: boolean;
  severity_counts: SeverityCounts;
}

export interface ComparedFinding {
  fingerprint: string;
  status: ComparisonStatus;
  rule_id: string;
  title: string;
  severity: Severity;
  base_score: number | null;
  target_score: number | null;
  base_finding_id: string | null;
  target_finding_id: string | null;
  reason: string | null;
}

export interface ComparedPath {
  fingerprint: string;
  status: ComparisonStatus;
  summary: string;
  classification: PathClassification;
  base_score: number | null;
  target_score: number | null;
  base_path_id: string | null;
  target_path_id: string | null;
  reason: string | null;
}

export interface RunComparison {
  base: RunSide;
  target: RunSide;
  findings: ComparedFinding[];
  finding_counts: StatusCounts;
  attack_paths: ComparedPath[];
  path_counts: StatusCounts;
  caveats: string[];
}

export interface ReportScope {
  run_id: string;
  started_at: string;
  completed_at: string | null;
  analysis_version: string;
  import_source: string;
  import_created_at: string;
  identity_count: number;
  resource_count: number;
  sensitive_resource_count: number;
  policy_count: number;
  statement_count: number;
}

export interface ReportFinding {
  id: string;
  rule_id: string;
  title: string;
  severity: Severity;
  risk_score: number;
  identity_name: string | null;
  resource_name: string | null;
  explanation: string;
  remediation: string;
}

export interface ReportPath {
  id: string;
  summary: string;
  classification: PathClassification;
  severity: Severity;
  risk_score: number;
  start: string;
  target: string;
  step_count: number;
}

export interface Report {
  generated_at: string;
  environment: { name: string; cloud_provider: string; description: string | null };
  scope: ReportScope;
  finding_total: number;
  severity_counts: SeverityCounts;
  findings: ReportFinding[];
  findings_not_shown: number;
  attack_path_total: number;
  attack_paths: ReportPath[];
  attack_paths_not_shown: number;
  paths_incomplete: boolean;
  ai_summary: AIAnalysis<SecuritySummaryContent> | null;
  limitations: string[];
}

export interface PermissionEntry {
  key: string;
  source_kind: "policy" | "trust" | "resource_policy";
  source_name: string;
  source_owner: string;
  statement_index: number;
  sid: string | null;
  effect: Effect;
  actions: string[];
  target_label: "resources" | "principals";
  targets: string[];
  conditions: Record<string, unknown>;
  related_identities: { id: string; name: string }[];
  related_findings: { id: string; title: string; severity: Severity; rule_id: string }[];
}

export interface PermissionList {
  total: number;
  items: PermissionEntry[];
}