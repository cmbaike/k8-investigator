// Fixed health-check errors. Only an exact code is shown; any other server
// text is untrusted and stays on the generic status message.
export const HEALTH_MESSAGES = {
  not_found: "That resource was not found in the selected namespace. No other workloads were checked.",
  namespace_denied: "That namespace is not available in this demo.",
  permission_denied: "The investigator is not allowed to read that resource.",
  unsupported_kind: "Health checks support Deployment and Pod only. This kind can still be investigated.",
  invalid_name: "Enter an exact resource name using lowercase letters, digits and hyphens.",
} as const;

export function knownHealthMessage(detail: unknown): string | null {
  return typeof detail === "string" && detail in HEALTH_MESSAGES
    ? HEALTH_MESSAGES[detail as keyof typeof HEALTH_MESSAGES]
    : null;
}
