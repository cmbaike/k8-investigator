// The backend's fixed scope-rejection messages (app/tools/investigation_scope.py,
// SCOPE_REJECTION_MESSAGES). Only an EXACT match is ever displayed from a 422
// response; any other server text is treated as untrusted and replaced by a
// generic message. tests/test_web_api.py checks this list stays in sync.
export const SCOPE_MESSAGES: Record<string, string> = {
  namespace_required: "A namespace is required: send the 'namespace' field.",
  namespace_invalid: "Invalid namespace name.",
  namespace_conflict: "The question refers to a namespace other than the one requested.",
  cluster_wide:
    "Cluster-wide or cross-namespace investigation is not supported; investigate one authorized namespace.",
  broader_access: "The question requests access beyond the authorized namespace.",
  state_change: "Investigations are read-only; the question requests a change.",
  question_empty: "The question must not be empty.",
  multiple_targets:
    "The question names more than one workload; ask about one workload at a time, or ask a broad question about the namespace.",
  ambiguous_scope:
    "The question names a workload and also asks about the rest of the namespace; ask about one workload, or ask a broad question about the namespace.",
  scope_unspecified:
    "The question does not say what to investigate: name one workload (for example 'Why is <name> failing?') or ask about the namespace as a whole (for example 'Investigate the health of the namespace').",
  invalid_target_name:
    "A name in the question is not a valid Kubernetes resource name (lowercase letters, digits and hyphens); check the spelling.",
  target_not_bindable:
    "That workload name cannot be bound as an explicit target (it may be a reserved word). Use the exact name of an existing workload.",
  question_too_long: "The question is too long once the scope is added.",
};

const KNOWN = new Set(Object.values(SCOPE_MESSAGES));

export function knownScopeMessage(detail: unknown): string | null {
  return typeof detail === "string" && KNOWN.has(detail) ? detail : null;
}
