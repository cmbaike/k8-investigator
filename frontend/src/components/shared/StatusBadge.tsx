import { CheckCircle2, CircleDashed, Loader2, XCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { InvestigationStatus, Severity } from "@/types/api";
import { SEVERITY_LABEL, SEVERITY_TONE, STATUS_LABEL, STATUS_TONE } from "./format";

const icons = { pending: CircleDashed, running: Loader2, completed: CheckCircle2, failed: XCircle } as const;

export function StatusBadge({ status }: { status: InvestigationStatus }) {
  const Icon = icons[status];

  return (
    <Badge tone={STATUS_TONE[status]}>
      <Icon aria-hidden="true" className={status === "running" ? "size-3 animate-spin" : "size-3"} />
      {STATUS_LABEL[status]}
    </Badge>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <Badge tone={SEVERITY_TONE[severity]}>{SEVERITY_LABEL[severity]}</Badge>;
}
