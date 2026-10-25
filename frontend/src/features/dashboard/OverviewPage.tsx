import { useQuery } from "@tanstack/react-query";
import { Inbox, PlusCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { endpoints } from "@/api/endpoints";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageHeader } from "@/components/shared/PageHeader";
import { QueryError } from "@/components/shared/QueryError";
import { formatDuration } from "@/components/shared/format";
import { Button } from "@/components/ui/button";
import { Card, CardHeader } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { InvestigationTable } from "@/features/investigations/InvestigationTable";

function Metric({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="space-y-0.5 bg-surface px-4 py-3">
      <p className="text-xs text-muted">{label}</p>
      <p className="text-xl font-semibold tabular-nums tracking-tight">{value}</p>
      <p className="h-4 text-xs text-muted">{note}</p>
    </div>
  );
}

export function OverviewPage() {
  const stats = useQuery({ queryKey: ["investigations", "stats"], queryFn: endpoints.stats });
  const recent = useQuery({
    queryKey: ["investigations", "list", { recent: true }],
    queryFn: () => endpoints.list({ limit: 5, offset: 0 }),
  });

  return (
    <>
      <PageHeader
        title="Overview"
        description="Read-only Kubernetes investigations grounded in verified evidence."
        actions={
          <Link to="/investigations/new">
            <Button variant="primary">
              <PlusCircle aria-hidden="true" className="size-3.5" />
              New investigation
            </Button>
          </Link>
        }
      />

      {stats.isError ? <QueryError error={stats.error} onRetry={() => void stats.refetch()} title="Could not load summary figures" /> : null}

      <section aria-label="Summary" className="grid grid-cols-2 gap-px overflow-hidden rounded-lg border border-border bg-border lg:grid-cols-4">
          {stats.isPending ? (
            Array.from({ length: 4 }, (_, index) => (
              <div key={index} className="space-y-1.5 bg-surface px-4 py-3">
                <Skeleton className="h-3 w-20" />
                <Skeleton className="h-6 w-12" />
                <Skeleton className="h-3 w-24" />
              </div>
            ))
          ) : stats.data ? (
            <>
              <Metric label="Investigations" value={String(stats.data.total)} note={stats.data.in_progress ? `${stats.data.in_progress} in progress` : undefined} />
              <Metric label="Completed" value={String(stats.data.completed)} note={stats.data.failed ? `${stats.data.failed} failed` : undefined} />
              <Metric label="Warning or higher" value={String(stats.data.completed_with_warning_or_higher)} note="completed, per report severity" />
              <Metric label="Average duration" value={formatDuration(stats.data.average_duration_seconds)} note="completed investigations" />
            </>
          ) : (
            <p className="col-span-full bg-surface px-4 py-6 text-[13px] text-muted">Summary figures are unavailable.</p>
          )}
      </section>

      <Card>
        <CardHeader>
          <h2 className="text-[13px] font-medium">Recent investigations</h2>
          <Link to="/investigations" className="text-xs text-accent hover:underline">
            View all
          </Link>
        </CardHeader>
        {recent.isPending ? (
          <div className="space-y-2 p-4" aria-busy="true" aria-label="Loading recent investigations">
            {Array.from({ length: 3 }, (_, index) => (
              <Skeleton key={index} className="h-8" />
            ))}
          </div>
        ) : recent.isError ? (
          <div className="p-4">
            <QueryError error={recent.error} onRetry={() => void recent.refetch()} />
          </div>
        ) : recent.data.items.length === 0 ? (
          <EmptyState
            icon={Inbox}
            title="No investigations have been run yet."
            hint="Pick a workload and the platform gathers read-only evidence."
            action={
              <Link to="/investigations/new" className="text-[13px] text-accent hover:underline">
                Run the first investigation
              </Link>
            }
          />
        ) : (
          <InvestigationTable items={recent.data.items} />
        )}
      </Card>
    </>
  );
}
