import type {
  AuditTrail,
  InvestigationPage,
  InvestigationReport,
  InvestigationStats,
  InvestigationSummary,
  AccessInfo,
} from "@/types/api";

// Typed samples shaped like real API responses. They exist only for tests; the
// application has no fixture or "sample data" mode.
export const ACCESS: AccessInfo = {
  allowed_namespaces: ["ai-ops-demo"],
};

export const ID = "9acee6e5-2af1-4cf1-8ab6-3aef262acf89";

export function summary(overrides: Partial<InvestigationSummary> = {}): InvestigationSummary {
  return {
    investigation_id: ID,
    authorized_namespace: "ai-ops-demo",
    status: "completed",
    created_at: "2026-10-18T10:00:00Z",
    started_at: "2026-10-18T10:00:01Z",
    finished_at: "2026-10-18T10:00:08Z",
    stop_reason: "provider_finished",
    user_text: "Investigate deployment/bad-readiness. Why is this workload unhealthy?",
    max_steps: 6,
    duration_seconds: 7,
    scope: { mode: "workload", kind: "Deployment", name: "bad-readiness" },
    primary_finding: { title: "Container is running but not ready", severity: "critical" },
    finding_counts: { critical: 1, warning: 0, info: 2, unknown: 0 },
    ...overrides,
  };
}

export const STATS: InvestigationStats = {
  total: 12,
  completed: 10,
  failed: 1,
  in_progress: 1,
  completed_with_warning_or_higher: 8,
  average_duration_seconds: 6.5,
};

export function page(items: InvestigationSummary[], total = items.length): InvestigationPage {
  return { items, total, limit: 10, offset: 0 };
}

export function report(overrides: Partial<InvestigationReport> = {}): InvestigationReport {
  return {
    investigation_id: ID,
    summary:
      "Investigation of namespace 'ai-ops-demo': 3 verified finding(s).\nMost significant findings:\n1. [critical] Container is running but not ready\nThe findings describe observed state only.",
    findings: [
      {
        title: "Container is running but not ready",
        description:
          "Container 'app' is running but Kubernetes reports it is not ready. Observed during tool execution 'k8s.describe_pod'. Resource: namespace 'ai-ops-demo', pod 'bad-readiness-abc'.",
        severity: "critical",
        evidence: [{ evidence_id: "ev-0005" }, { evidence_id: "ev-0007" }],
      },
      {
        title: "Pod phase observed",
        description: "Kubernetes reported pod phase 'Running'.",
        severity: "info",
        evidence: [{ evidence_id: "ev-0003" }],
      },
      {
        title: "Container configuration observed",
        description: "Container 'app': image 'nginx:1.27'.",
        severity: "info",
        evidence: [{ evidence_id: "ev-0009" }],
      },
    ],
    uncertainties: ["Container logs were not retrieved, so no application output was available."],
    suggested_checks: ["Review the readiness probe path through read-only describe output."],
    ai_hypotheses: [
      {
        explanation: "Possible explanation (unverified): composed text.",
        status: "unverified",
        reported: null,
        possible_explanation: "The readiness probe may be failing because its path is wrong.",
        not_yet_verified: "It has not been verified whether the probe path exists.",
        evidence_refs: ["ev-0005", "ev-0042"],
        resource: { namespace: "ai-ops-demo", pod: "bad-readiness-abc", container: "app" },
        verification_check: "Inspect the declared probe through read-only describe output.",
        independently_established: "The container is running and readiness is false.",
        established_refs: ["ev-0007"],
        configuration_context: null,
        configuration_refs: [],
      },
    ],
    ai_analysis: {
      state: "generated",
      reason: null,
      message: "1 hypothesis accepted after validation.",
      log_excerpts_used: 0,
      log_excerpts_omitted: 0,
      hypotheses_omitted: 2,
      hypotheses_proposed: 3,
      omission_reasons: { insufficiently_cautious: 1, too_many_references: 1 },
      rejection_category: null,
    },
    ...overrides,
  };
}

export function audit(overrides: Partial<AuditTrail> = {}): AuditTrail {
  const base = { request_id: "run-1", tool_call_id: null, arguments: { namespace: "ai-ops-demo" } };

  return {
    investigation_id: ID,
    truncated: false,
    events: [
      { ...base, event_id: "e1", event_type: "proposed", tool_name: "k8s.get_pods", status: "received", reason_code: null, created_at: "2026-10-18T10:00:02Z" },
      { ...base, event_id: "e2", event_type: "authorized", tool_name: "k8s.get_pods", status: "allowed", reason_code: null, created_at: "2026-10-18T10:00:02Z" },
      { ...base, event_id: "e3", event_type: "proposed", tool_name: "k8s.get_logs", status: "received", reason_code: null, created_at: "2026-10-18T10:00:03Z", arguments: { namespace: "ai-ops-demo", pod: "other-pod" } },
      { ...base, event_id: "e4", event_type: "rejected", tool_name: "k8s.get_logs", status: "denied", reason_code: "outside_target", created_at: "2026-10-18T10:00:03Z", arguments: { namespace: "ai-ops-demo", pod: "other-pod" } },
    ],
    ...overrides,
  };
}
