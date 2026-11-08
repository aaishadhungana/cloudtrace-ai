import type { Decision, RelationshipType, RiskFactor, Severity } from "@/lib/analysis-types";

export type PathClassification = "supported" | "potential";
export type PathSort = "score_desc" | "score_asc";

export interface AttackPathSummary {
  id: string;
  analysis_run_id: string;
  start_identity_id: string;
  start_identity_name: string;
  target_resource_id: string;
  target_resource_name: string;
  classification: PathClassification;
  risk_score: number;
  severity: Severity;
  step_count: number;
  summary: string;
  created_at: string;
}

export interface PathNodeInfo {
  id: string | null;
  arn: string;
  name: string;
  kind: string;
  type: string;
  is_external: boolean;
  is_sensitive: boolean;
  position: string;
}

export interface PathEdgeInfo {
  source: string;
  target: string;
  relationship: RelationshipType;
  relationships: RelationshipType[];
  decision: Decision;
  actions: string[];
  notes: string[];
  assumption: string | null;
}

export interface AttackPathDetail extends AttackPathSummary {
  raw_score: number;
  risk_factors: RiskFactor[];
  nodes: PathNodeInfo[];
  edges: PathEdgeInfo[];
  evidence: Record<string, unknown>[];
}

export interface AttackPathList {
  total: number;
  items: AttackPathSummary[];
}

export interface AttackPathQuery {
  classification?: PathClassification;
  minScore?: number;
  startIdentityId?: string;
  targetResourceId?: string;
  sort?: PathSort;
}