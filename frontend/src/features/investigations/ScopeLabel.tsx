import { Badge } from "@/components/ui/badge";
import type { ScopeSummary } from "@/types/api";

export function scopeText(scope: ScopeSummary): string {
  if (scope.mode === "workload" && scope.name) {
    return scope.kind ? `${scope.kind}/${scope.name}` : scope.name;
  }

  return scope.mode === "namespace" ? "Whole namespace" : "Scope not stated";
}

export function ScopeLabel({ scope }: { scope: ScopeSummary }) {
  if (scope.mode === "namespace") {
    return <Badge tone="warning">Namespace-wide</Badge>;
  }

  return <span className="font-mono text-xs">{scopeText(scope)}</span>;
}
