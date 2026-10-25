import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowLeft, Play, RefreshCw } from "lucide-react";
import { useRef } from "react";
import { Link, useParams } from "react-router-dom";
import { ApiError } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import { Callout } from "@/components/shared/Callout";
import { QueryError } from "@/components/shared/QueryError";
import { StatusBadge } from "@/components/shared/StatusBadge";
import { formatDuration, formatTimestamp } from "@/components/shared/format";
import { Badge } from "@/components/ui/badge";
import { Disclosure } from "@/components/ui/disclosure";
import { Button } from "@/components/ui/button";
import { Card, CardBody } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { AuditPanel, AuditTrailSection, auditCounts } from "@/features/audit/AuditTrailSection";
import { SpokenSummary } from "@/features/speech/SpokenSummary";
import { startExecution, useExecutionState } from "./execution";
import { ReportView } from "./ReportView";
import type { InvestigationStatus, InvestigationSummary } from "@/types/api";

export const POLL_INTERVAL_MS = 2000;
// Polling is bounded: it stops at a terminal status or after this long.
export const POLL_LIMIT_MS = 10 * 60 * 1000;

const FAILURE_EXPLANATIONS: Record<string, string> = {
  tool_failed:
    "A read-only Kubernetes call failed (for example an authorization or connectivity error), so no report was produced.",
  execution_failed: "Execution failed on the server, so no report was produced.",
};

function isActive(status: InvestigationStatus | undefined): boolean {
  return status === "pending" || status === "running";
}

function Header({ summary }: { summary: InvestigationSummary }) {
  const scope = summary.scope;
  const namespaceWide = scope.mode === "namespace";
  const title = namespaceWide ? "Whole namespace" : (scope.name ?? "Scope not stated");
  const details: [string, string, boolean][] = [
    ["Investigation ID", summary.investigation_id, true],
    ["Created", formatTimestamp(summary.created_at), false],
    ["Started", formatTimestamp(summary.started_at), false],
    ["Finished", formatTimestamp(summary.finished_at), false],
    ["Step budget", summary.max_steps === null ? "—" : `${summary.max_steps} read-only calls`, false],
    ["Stop reason", summary.stop_reason ?? "—", true],
  ];

  return (
    <header className="space-y-2.5">
      <Link to="/investigations" className="inline-flex items-center gap-1 text-xs text-muted hover:text-foreground">
        <ArrowLeft aria-hidden="true" className="size-3" />
        History
      </Link>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5">
        <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
        {!namespaceWide && scope.kind ? <Badge>{scope.kind}</Badge> : null}
        <StatusBadge status={summary.status} />
        {namespaceWide ? <Badge tone="warning">Namespace-wide</Badge> : null}
      </div>
      <dl className="flex flex-wrap gap-x-5 gap-y-1 text-[13px] text-muted">
        <div className="flex gap-1.5">
          <dt>Namespace</dt>
          <dd className="font-mono text-foreground">{summary.authorized_namespace}</dd>
        </div>
        <div className="flex gap-1.5">
          <dt>Duration</dt>
          <dd className="text-foreground tabular-nums">{formatDuration(summary.duration_seconds)}</dd>
        </div>
        <div className="flex gap-1.5">
          <dt>Scope</dt>
          <dd className="text-foreground">{namespaceWide ? "whole namespace" : "one workload"} · read-only</dd>
        </div>
      </dl>
      <Disclosure
        className="w-fit max-w-full rounded-md border border-border bg-surface"
        summary={<span className="text-xs text-muted">Details</span>}
      >
        <dl className="grid grid-cols-1 gap-x-6 gap-y-2 text-xs sm:grid-cols-2">
          {details.map(([label, value, mono]) => (
            <div key={label} className="min-w-0">
              <dt className="text-muted">{label}</dt>
              <dd className={mono ? "break-all font-mono" : "tabular-nums"}>{value}</dd>
            </div>
          ))}
        </dl>
        {summary.user_text ? (
          <div className="text-xs">
            <p className="text-muted">Question as recorded</p>
            <p>{summary.user_text}</p>
          </div>
        ) : null}
      </Disclosure>
    </header>
  );
}

export function DetailPage() {
  const { id = "" } = useParams();
  const queryClient = useQueryClient();
  const startedAt = useRef(Date.now());
  const execution = useExecutionState(id);

  const summary = useQuery({
    queryKey: ["investigation", id, "summary"],
    queryFn: () => endpoints.summary(id),
    refetchInterval: (query) =>
      isActive(query.state.data?.status) && Date.now() - startedAt.current < POLL_LIMIT_MS ? POLL_INTERVAL_MS : false,
  });

  const status = summary.data?.status;
  const completed = status === "completed";
  const pollingStopped =
    isActive(status) && Date.now() - startedAt.current >= POLL_LIMIT_MS && !summary.isFetching;

  const report = useQuery({
    queryKey: ["investigation", id, "report"],
    queryFn: () => endpoints.report(id),
    enabled: completed,
  });

  const audit = useQuery({
    queryKey: ["investigation", id, "audit"],
    queryFn: () => endpoints.audit(id),
    enabled: summary.isSuccess,
  });

  if (summary.isPending) {
    return (
      <div className="space-y-4" aria-busy="true" aria-label="Loading investigation">
        <Skeleton className="h-7 w-64" />
        <Skeleton className="h-4 w-96 max-w-full" />
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
      </div>
    );
  }

  if (summary.isError) {
    const notFound = summary.error instanceof ApiError && summary.error.kind === "not_found";

    return (
      <div className="space-y-4">
        <Callout
          tone={notFound ? "warning" : "error"}
          title={notFound ? "Investigation not found" : "Could not load the investigation"}
          action={
            notFound ? undefined : (
              <Button size="sm" onClick={() => void summary.refetch()}>
                <RefreshCw aria-hidden="true" className="size-3.5" />
                Retry
              </Button>
            )
          }
        >
          {summary.error instanceof ApiError ? summary.error.message : "An unexpected error occurred."}
          {notFound ? " It may not exist." : ""}
        </Callout>
        <Link to="/investigations" className="text-sm text-accent hover:underline">
          Back to history
        </Link>
      </div>
    );
  }

  const record = summary.data;
  const { rejected, total: auditTotal } = auditCounts(audit.data?.events ?? []);

  return (
    <div className="space-y-5">
      <Header summary={record} />

      {execution?.phase === "failed" ? (
        <Callout tone="warning" title="The execute request did not complete normally">
          {execution.message}
        </Callout>
      ) : null}

      {record.status === "pending" ? (
        <Callout
          tone="info"
          title="Pending: not started"
          action={
            execution === undefined ? (
              <Button variant="primary" size="sm" onClick={() => startExecution(queryClient, id)}>
                <Play aria-hidden="true" className="size-3.5" />
                Start investigation
              </Button>
            ) : undefined
          }
        >
          {execution === undefined
            ? "Created but not started. Starting runs the read-only checks once."
            : "Execution was requested from this tab. Waiting for the server to report that it started."}
        </Callout>
      ) : null}

      {record.status === "running" ? (
        <Callout tone="info" title="Running">
          Running read-only checks. This page refreshes every {POLL_INTERVAL_MS / 1000} seconds and shows only what the
          backend reports.
        </Callout>
      ) : null}

      {pollingStopped ? (
        <Callout
          tone="warning"
          title="Automatic refresh stopped"
          action={
            <Button
              size="sm"
              onClick={() => {
                startedAt.current = Date.now();
                void summary.refetch();
              }}
            >
              <RefreshCw aria-hidden="true" className="size-3.5" />
              Refresh
            </Button>
          }
        >
          The investigation is still {record.status} after 10 minutes. It may have lost its execution lease; the
          server marks such runs as failed.
        </Callout>
      ) : null}

      {record.status === "failed" ? (
        <>
          <Callout tone="error" title="Investigation failed">
            {(record.stop_reason && FAILURE_EXPLANATIONS[record.stop_reason]) ??
              "The investigation did not complete, so there is no report."}{" "}
            No findings or hypotheses were persisted. The audit trail records what ran.
          </Callout>
          <SpokenSummary investigationId={id} />
        </>
      ) : null}

      {completed ? (
        report.isPending ? (
          <div className="space-y-4" aria-busy="true" aria-label="Loading report">
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <Skeleton className="h-40" />
              <Skeleton className="h-40" />
            </div>
            <Skeleton className="h-32" />
          </div>
        ) : report.isError ? (
          <QueryError error={report.error} onRetry={() => void report.refetch()} title="Could not load the report" />
        ) : (
          <>
            <SpokenSummary investigationId={id} />
            <ReportView
              report={report.data}
              rejectedProposals={rejected}
              stopReason={record.stop_reason}
              auditPanel={<AuditPanel investigationId={id} refetchWhileActive={false} />}
              auditCount={audit.data ? auditTotal : null}
              scopeMode={record.scope.mode}
            />
          </>
        )
      ) : (
        <>
          {record.status === "failed" ? null : (
            <Card>
              <CardBody className="text-[13px] text-muted">The report appears here when the investigation completes.</CardBody>
            </Card>
          )}
          <AuditTrailSection investigationId={id} refetchWhileActive={isActive(record.status)} />
        </>
      )}
    </div>
  );
}
