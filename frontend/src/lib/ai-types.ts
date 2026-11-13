export interface AIStatus {
  available: boolean;
  model: string | null;
  reason: string | null;
}

export interface AIAnalysis<C> {
  subject_type: "finding" | "attack_path" | "summary";
  subject_id: string | null;
  model: string;
  generated_at: string;
  cached: boolean;
  notice: string;
  content: C;
}

export interface RemediationStep {
  action: string;
  rationale: string;
  verify_before_applying: string;
}

export interface FindingAnalysisContent {
  what_was_detected: string;
  why_it_is_risky: string;
  potential_impact: string;
  evidence_established: string[];
  remaining_uncertainty: string[];
  remediation: RemediationStep[];
}

export interface AttackPathAnalysisContent {
  overview: string;
  steps: { step: number; explanation: string }[];
  potential_impact: string;
  why_it_deserves_attention: string;
  verify_before_claiming_exploitability: string[];
  remediation: RemediationStep[];
}

export interface SecuritySummaryContent {
  overview: string;
  priorities: { title: string; why: string; recommended_action: string }[];
  caveats: string[];
}