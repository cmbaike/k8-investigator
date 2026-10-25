import { Link } from "react-router-dom";
import { SeverityBadge, StatusBadge } from "@/components/shared/StatusBadge";
import { formatCompact, formatDuration, shortId } from "@/components/shared/format";
import type { InvestigationSummary } from "@/types/api";
import { ScopeLabel } from "./ScopeLabel";

const HEAD = "px-3 py-2 sm:px-4 text-xs font-medium text-muted";
const CELL = "px-3 py-2 sm:px-4";

// Namespace, duration and time drop out on narrow screens; the row stays
// readable without horizontal scrolling.
export function InvestigationTable({ items }: { items: InvestigationSummary[] }) {
  return (
    <div className="relative overflow-x-auto">
      <table className="w-full text-left text-[13px]">
        <caption className="sr-only">Investigations</caption>
        <thead>
          <tr className="border-b border-border">
            <th scope="col" className={HEAD}>Target</th>
            <th scope="col" className={`${HEAD} hidden md:table-cell`}>Namespace</th>
            <th scope="col" className={HEAD}>Status</th>
            <th scope="col" className={HEAD}>Primary verified finding</th>
            <th scope="col" className={`${HEAD} hidden lg:table-cell`}>Duration</th>
            <th scope="col" className={`${HEAD} hidden sm:table-cell`}>Created</th>
            <th scope="col" className={HEAD}>
              <span className="sr-only">Report</span>
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-border">
          {items.map((item) => (
            <tr key={item.investigation_id} className="transition-colors hover:bg-surface-2/50">
              <td className={CELL}>
                <ScopeLabel scope={item.scope} />
              </td>
              <td className={`${CELL} hidden whitespace-nowrap font-mono text-xs text-muted md:table-cell`}>{item.authorized_namespace}</td>
              <td className={CELL}>
                <StatusBadge status={item.status} />
              </td>
              <td className={CELL}>
                {item.primary_finding ? (
                  <span className="flex items-center gap-2">
                    <SeverityBadge severity={item.primary_finding.severity} />
                    <span>{item.primary_finding.title}</span>
                  </span>
                ) : (
                  <span className="text-muted">{item.status === "completed" ? "No findings recorded" : "—"}</span>
                )}
              </td>
              <td className={`${CELL} hidden text-muted tabular-nums lg:table-cell`}>{formatDuration(item.duration_seconds)}</td>
              <td className={`${CELL} hidden whitespace-nowrap text-muted tabular-nums sm:table-cell`}>{formatCompact(item.created_at)}</td>
              <td className={`${CELL} text-right`}>
                <Link
                  to={`/investigations/${encodeURIComponent(item.investigation_id)}`}
                  className="text-accent hover:underline"
                  aria-label={`Open investigation ${shortId(item.investigation_id)}`}
                >
                  Open
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
