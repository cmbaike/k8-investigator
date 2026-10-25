import type { AuditEventType } from "@/types/api";

export const EVENT_LABEL: Record<AuditEventType, string> = {
  proposed: "Proposed",
  authorized: "Authorized",
  rejected: "Rejected",
  execution_started: "Execution started",
  completed: "Completed",
};

// Fixed rejection reasons (app/tools/proposal_rejection.py). Anything else is
// shown as the raw code, never as prose.
export const REJECTION_REASONS: Record<string, string> = {
  outside_target: "The call would inspect something other than the bound workload.",
  target_unresolved: "The target workload could not be resolved, so no pod call was permitted.",
  namespace_wide_events: "A namespace-wide events read was refused for a targeted investigation.",
};
