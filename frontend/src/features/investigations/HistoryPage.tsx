import { keepPreviousData, useQuery } from "@tanstack/react-query";
import { ChevronLeft, ChevronRight, Inbox, PlusCircle } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { endpoints } from "@/api/endpoints";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageHeader } from "@/components/shared/PageHeader";
import { QueryError } from "@/components/shared/QueryError";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Select } from "@/components/ui/field";
import { Skeleton } from "@/components/ui/skeleton";
import type { InvestigationStatus } from "@/types/api";
import { InvestigationTable } from "./InvestigationTable";

export const PAGE_SIZE = 10;
const STATUSES: InvestigationStatus[] = ["pending", "running", "completed", "failed"];

function parseStatus(value: string | null): InvestigationStatus | undefined {
  return STATUSES.find((status) => status === value);
}

export function HistoryPage() {
  const [params, setParams] = useSearchParams();
  const status = parseStatus(params.get("status"));
  const page = Math.max(0, Number.parseInt(params.get("page") ?? "0", 10) || 0);

  const query = useQuery({
    queryKey: ["investigations", "list", { status, page }],
    queryFn: () => endpoints.list({ limit: PAGE_SIZE, offset: page * PAGE_SIZE, status }),
    placeholderData: keepPreviousData,
  });

  function update(next: { status?: string; page?: number }) {
    const copy = new URLSearchParams(params);
    if (next.status !== undefined) {
      if (next.status) copy.set("status", next.status);
      else copy.delete("status");
      copy.delete("page");
    }
    if (next.page !== undefined) {
      if (next.page > 0) copy.set("page", String(next.page));
      else copy.delete("page");
    }
    setParams(copy);
  }

  const total = query.data?.total ?? 0;
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <>
      <PageHeader
        title="Investigation history"
        description="Persisted investigations in your namespaces."
        actions={
          <Link to="/investigations/new">
            <Button variant="primary">
              <PlusCircle aria-hidden="true" className="size-3.5" />
              New investigation
            </Button>
          </Link>
        }
      />

      <div className="flex items-center gap-2">
        <label htmlFor="status-filter" className="text-[13px] text-muted">
          Status
        </label>
        <Select
          id="status-filter"
          className="w-40"
          value={status ?? ""}
          onChange={(event) => update({ status: event.target.value })}
        >
          <option value="">All</option>
          {STATUSES.map((value) => (
            <option key={value} value={value}>
              {value[0]?.toUpperCase()}
              {value.slice(1)}
            </option>
          ))}
        </Select>
      </div>

      {query.isError ? <QueryError error={query.error} onRetry={() => void query.refetch()} /> : null}

      <Card>
        {query.isPending ? (
          <div className="space-y-2 p-4" aria-busy="true" aria-label="Loading investigations">
            {Array.from({ length: 5 }, (_, index) => (
              <Skeleton key={index} className="h-9" />
            ))}
          </div>
        ) : query.data && query.data.items.length > 0 ? (
          <InvestigationTable items={query.data.items} />
        ) : query.data ? (
          <EmptyState
            icon={Inbox}
            title={status ? "No investigations have this status." : "No investigations have been run yet."}
            hint={status ? "Clear the status filter to see everything." : undefined}
          />
        ) : null}

        {query.data && total > 0 ? (
          <nav
            aria-label="Pagination"
            className="flex items-center justify-between border-t border-border px-4 py-2 text-xs text-muted"
          >
            <span>
              Page {page + 1} of {pages} · {total} total
            </span>
            <span className="flex gap-2">
              <Button size="sm" disabled={page === 0} onClick={() => update({ page: page - 1 })}>
                <ChevronLeft aria-hidden="true" className="size-3.5" />
                Previous
              </Button>
              <Button size="sm" disabled={page + 1 >= pages} onClick={() => update({ page: page + 1 })}>
                Next
                <ChevronRight aria-hidden="true" className="size-3.5" />
              </Button>
            </span>
          </nav>
        ) : null}
      </Card>
    </>
  );
}
