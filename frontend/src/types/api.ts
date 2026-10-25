// Types mirror the backend's response models (app/web/models.py,
// app/investigations/models.py, app/reports/models.py). Nothing here is
// invented: a field that the API does not return does not appear.

export type InvestigationStatus = "pending" | "running" | "completed" | "failed";
export type Severity = "info" | "warning" | "critical" | "unknown";

export interface AccessInfo {
  allowed_namespaces: string[];
}

export interface HealthInfo {
  status: "ok" | "degraded";
  database: boolean;
}

export interface InvestigationRecord {
  investigation_id: string;
  authorized_namespace: string;
  status: InvestigationStatus;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  stop_reason: string | null;
  user_text: string | null;
  max_steps: number | null;
}

export interface ScopeSummary {
  mode: "workload" | "namespace" | "unspecified";
  kind: string | null;
  name: string | null;
}

export interface PrimaryFinding {
  title: string;
  severity: Severity;
}

export interface FindingCounts {
  critical: number;
  warning: number;
  info: number;
  unknown: number;
}

export interface InvestigationSummary extends InvestigationRecord {
  duration_seconds: number | null;
  scope: ScopeSummary;
  primary_finding: PrimaryFinding | null;
  finding_counts: FindingCounts | null;
}

export interface InvestigationPage {
  items: InvestigationSummary[];
  total: number;
  limit: number;
  offset: number;
}

export interface InvestigationStats {
  total: number;
  completed: number;
  failed: number;
  in_progress: number;
  completed_with_warning_or_higher: number;
  average_duration_seconds: number | null;
}

export type TargetKind = "Deployment" | "StatefulSet" | "DaemonSet" | "Pod";

export interface SpeechProposal {
  outcome: "workload" | "namespace" | "clarify";
  name: string | null;
  kind: TargetKind | null;
  code: string | null;
}

export interface CreateInvestigationRequest {
  namespace: string;
  question: string;
  max_steps?: number;
  target?: { kind: TargetKind; name: string };
  namespace_wide?: boolean;
}

export interface EvidenceReference {
  evidence_id: string;
}

/**
 * One scheduler constraint Kubernetes reported for an unschedulable pod. The
 * backend mints these from validated, fixed-vocabulary signals: the label is
 * its own text (never an event message), and the ids are the signal
 * observations that establish it.
 */
export interface SchedulingConstraint {
  signal: string;
  label: string;
  evidence_ids: string[];
}

export interface Finding {
  title: string;
  description: string;
  severity: Severity;
  evidence: EvidenceReference[];
  /** Absent in reports stored before the field existed. */
  scheduling_constraints?: SchedulingConstraint[];
}

export interface HypothesisResource {
  namespace: string;
  pod: string | null;
  container: string | null;
}

export interface Hypothesis {
  explanation: string;
  status: "unverified";
  reported: string | null;
  possible_explanation: string;
  not_yet_verified: string;
  evidence_refs: string[];
  resource: HypothesisResource;
  /** Null when the application withheld the model's check; see `check_withheld_reason`. */
  verification_check: string | null;
  check_withheld_reason?: string | null;
  independently_established: string | null;
  established_refs: string[];
  configuration_context: string | null;
  configuration_refs: string[];
}

export type AiState = "generated" | "all_omitted" | "none_proposed" | "unavailable" | "not_attempted";

export interface AiAnalysis {
  state: AiState;
  reason: string | null;
  message: string;
  log_excerpts_used: number;
  log_excerpts_omitted: number;
  hypotheses_omitted: number;
  hypotheses_proposed: number;
  omission_reasons: Record<string, number>;
  rejection_category: "provenance" | "security" | "structure" | null;
}

export interface SpokenBriefing {
  text: string;
  speech_available: boolean;
}

export interface DiagnosticCheck {
  text: string;
  source: "hypothesis" | "report";
  hypothesis_index: number | null;
  pod: string | null;
  container: string | null;
}

export interface DiagnosticFinding {
  index: number;
  pod: string | null;
}

export interface DiagnosticResource {
  namespace: string;
  kind: "Deployment" | "StatefulSet" | "DaemonSet" | "Job" | "ReplicaSet" | "Pod";
  name: string;
  ownership: "verified" | "unresolved";
  pods: string[];
  findings: DiagnosticFinding[];
  hypothesis_indexes: number[];
  checks: DiagnosticCheck[];
  /** Absent on reports stored before coverage was recorded. */
  coverage?: "established" | "unknown" | "failed";
  deeply_investigated?: boolean;
}

/** Present for a namespace-wide investigation. Absent on older stored reports. */
export interface NamespaceDiagnostic {
  listed_pods: number;
  inspected_pods: number;
  uninspected_pods?: number;
  unsuccessful_pods?: number;
  listing_truncated?: boolean;
  /** False when health inspection did not cover the listing. Null when unknown. */
  assessment_complete?: boolean | null;
  resources: DiagnosticResource[];
  shared_findings: DiagnosticFinding[];
  shared_hypothesis_indexes: number[];
  shared_checks: DiagnosticCheck[];
}

export interface InvestigationReport {
  investigation_id: string;
  summary: string;
  findings: Finding[];
  uncertainties: string[];
  suggested_checks: string[];
  ai_hypotheses: Hypothesis[];
  ai_analysis: AiAnalysis | null;
  namespace_diagnostic?: NamespaceDiagnostic | null;
}

export type AuditEventType =
  | "proposed"
  | "authorized"
  | "rejected"
  | "execution_started"
  | "completed";

export interface AuditEvent {
  event_id: string;
  request_id: string | null;
  tool_call_id: string | null;
  event_type: AuditEventType;
  tool_name: string;
  arguments: Record<string, string | number>;
  status: string;
  reason_code: string | null;
  created_at: string;
}

export interface AuditTrail {
  investigation_id: string;
  events: AuditEvent[];
  truncated: boolean;
}

export type ResourceHealthCategory = "healthy" | "degraded" | "unhealthy" | "unknown";

export interface HealthSignal {
  code: string;
  label: string;
}

export interface HealthLimitation {
  code: string;
  label: string;
}

export interface ContainerHealth {
  name: string;
  ready: boolean | null;
  state: "waiting" | "running" | "terminated" | null;
  waiting_reason: string | null;
  last_termination_reason: string | null;
  last_exit_code: number | null;
  restart_count: number | null;
  configured_memory_request: string | null;
  configured_memory_limit: string | null;
}

export interface PodHealth {
  name: string;
  uid: string | null;
  phase: string | null;
  ready: boolean | null;
  category: ResourceHealthCategory;
  signals: HealthSignal[];
  containers: ContainerHealth[];
}

export interface ResourceHealth {
  resource: { namespace: string; kind: "Pod" | "Deployment"; name: string; uid: string | null };
  category: ResourceHealthCategory;
  signals: HealthSignal[];
  workload: { desired: number | null; ready: number | null; available: number | null; updated: number | null } | null;
  pods: PodHealth[];
  coverage: {
    discovered: number;
    examined: number;
    complete: boolean;
    summary: string;
    limitations: HealthLimitation[];
  };
  observed_at: string;
  ttl_seconds: number;
  snapshot: "point_in_time";
}

