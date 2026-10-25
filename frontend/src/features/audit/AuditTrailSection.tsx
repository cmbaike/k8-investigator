import { useQuery } from "@tanstack/react-query";
import { endpoints } from "@/api/endpoints";
import { QueryError } from "@/components/shared/QueryError";
import { formatClock, formatTimestamp } from "@/components/shared/format";
import { Badge } from "@/components/ui/badge";
import { Card, CardBody, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib";
import type { AuditEvent, AuditEventType } from "@/types/api";
import { EVENT_LABEL, REJECTION_REASONS } from "./auditLabels";

const TONE: Record<AuditEventType, "neutral" | "ok" | "critical" | "info"> = {
  proposed: "neutral",
  authorized: "ok",
  rejected: "critical",
  execution_started: "info",
  completed: "ok",
};

function Args({ args }: { args: AuditEvent["arguments"] }) {
  const entries = Object.entries(args);

  if (entries.length === 0) return <span className="text-xs text-muted">no identifiers</span>;

  return (
    <span className="min-w-0 break-all font-mono text-xs text-muted">
      {entries.map(([key, value]) => `${key}=${value}`).join("  ")}
    </span>
  );
}

export function useAuditTrail(investigationId: string, refetchWhileActive: boolean) {
  return useQuery({
    queryKey: ["investigation", investigationId, "audit"],
    queryFn: () => endpoints.audit(investigationId),
    refetchInterval: refetchWhileActive ? 3000 : false,
  });
}

export function auditCounts(events: AuditEvent[]) {
  return { total: events.length, rejected: events.filter((event) => event.event_type === "rejected").length };
}

// The audit list itself, without surrounding chrome, so it can sit in a tab.
export function AuditPanel({ investigationId, refetchWhileActive }: { investigationId: string; refetchWhileActive: boolean }) {
  const query = useAuditTrail(investigationId, refetchWhileActive);
  const events = query.data?.events ?? [];
  const { total, rejected } = auditCounts(events);

  if (query.isPending) {
    return (
      <div className="space-y-2" aria-busy="true" aria-label="Loading audit trail">
        {Array.from({ length: 3 }, (_, index) => (
          <Skeleton key={index} className="h-7" />
        ))}
      </div>
    );
  }

  if (query.isError) {
    return <QueryError error={query.error} onRetry={() => void query.refetch()} title="Could not load the audit trail" />;
  }

  if (events.length === 0) {
    return <p className="text-[13px] text-muted">No audit events are recorded for this investigation.</p>;
  }

  return (
    <div className="space-y-3">
      <p className="text-[13px] text-muted">
        {total} event{total === 1 ? "" : "s"}
        {rejected ? ` · ${rejected} rejected` : ""}. Tool proposals, authorization decisions and executions, as recorded
        by the backend. Only names and fixed codes are shown.
      </p>
      <ol className="divide-y divide-border overflow-hidden rounded-md border border-border" aria-label="Audit events">
        {events.map((event) => (
          <li
            key={event.event_id}
            className={cn("grid grid-cols-[auto_1fr] items-baseline gap-x-3 gap-y-0.5 px-3 py-1.5 sm:grid-cols-[4.5rem_6.5rem_1fr_auto]", event.event_type === "rejected" && "bg-critical/5")}
          >
            <time dateTime={event.created_at} title={formatTimestamp(event.created_at)} className="font-mono text-xs text-muted tabular-nums">
              {formatClock(event.created_at)}
            </time>
            <span>
              <Badge tone={TONE[event.event_type]}>{EVENT_LABEL[event.event_type]}</Badge>
            </span>
            <span className="col-span-2 flex min-w-0 flex-wrap items-baseline gap-x-2 sm:col-span-1">
              <span className="font-mono text-[13px]">{event.tool_name}</span>
              <Args args={event.arguments} />
            </span>
            <span className="hidden text-xs text-muted sm:block">
              status <span className="font-mono">{event.status}</span>
            </span>
            {event.reason_code ? (
              <p className="col-span-2 text-xs text-muted sm:col-start-3 sm:col-span-2">
                Reason <span className="font-mono text-foreground">{event.reason_code}</span>
                {REJECTION_REASONS[event.reason_code] ? ` — ${REJECTION_REASONS[event.reason_code]}` : ""}
              </p>
            ) : null}
          </li>
        ))}
      </ol>
      {query.data?.truncated ? (
        <p className="text-xs text-warning">The record is longer than this view; only the first events are shown.</p>
      ) : null}
    </div>
  );
}

// Stand-alone audit card for investigations that have no report (failed, pending, running).
export function AuditTrailSection({ investigationId, refetchWhileActive }: { investigationId: string; refetchWhileActive: boolean }) {
  return (
    <Card id="audit">
      <CardHeader>
        <h2 className="text-sm font-medium">Audit trail</h2>
      </CardHeader>
      <CardBody>
        <AuditPanel investigationId={investigationId} refetchWhileActive={refetchWhileActive} />
      </CardBody>
    </Card>
  );
}
