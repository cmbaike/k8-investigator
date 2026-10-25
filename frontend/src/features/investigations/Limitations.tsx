import type { ReactNode } from "react";
import type { InvestigationReport } from "@/types/api";
import { AI_REASON_LABELS, OMISSION_LABELS, parseSummary } from "./reportModel";

// Every uncertainty the report and the audit record carry, in one list. The
// closing caveat is stated once, here.
export function buildLimitations(report: InvestigationReport, rejectedProposals: number, stopReason: string | null): ReactNode[] {
  const ai = report.ai_analysis;
  const items: ReactNode[] = [];

  for (const text of report.uncertainties) items.push(text);

  if (ai?.state === "unavailable") {
    items.push(
      `AI analysis was unavailable${ai.reason ? ` (${AI_REASON_LABELS[ai.reason] ?? ai.reason})` : ""}. Verified findings are unaffected.`,
    );
  }

  if (ai && ai.hypotheses_omitted > 0) {
    const reasons = Object.entries(ai.omission_reasons).map(([code, count]) => `${OMISSION_LABELS[code] ?? code} (×${count})`);

    items.push(
      `${ai.hypotheses_omitted} of ${ai.hypotheses_proposed} proposed AI hypotheses were omitted by validation${reasons.length > 0 ? `: ${reasons.join("; ")}` : ""}.`,
    );
  }

  if (ai) {
    items.push(
      ai.log_excerpts_used === 0
        ? "No log excerpts were used by the AI analysis."
        : `${ai.log_excerpts_used} log excerpt(s) were used by the AI analysis${ai.log_excerpts_omitted ? `; ${ai.log_excerpts_omitted} more were omitted` : ""}. Log text is untrusted.`,
    );
  }

  if (rejectedProposals > 0) {
    items.push(
      `${rejectedProposals} model-proposed tool call${rejectedProposals === 1 ? " was" : "s were"} rejected by the application and never executed (see Audit).`,
    );
  }

  for (const note of parseSummary(report.summary).notes) items.push(note);

  if (stopReason) {
    items.push(
      <>
        The run stopped with reason <code className="font-mono text-xs">{stopReason}</code>.
      </>,
    );
  }

  items.push(
    "Findings describe observed Kubernetes state. They do not establish a root cause, and the absence of warning-or-higher findings does not show that the workload is healthy.",
  );

  return items;
}

export function LimitationsPanel({ items }: { items: ReactNode[] }) {
  return (
    <ul className="space-y-2" aria-label="Limitations and uncertainties">
      {items.map((item, position) => (
        <li key={position} className="flex gap-2.5 text-[13px]">
          <span aria-hidden="true" className="mt-[7px] size-1 shrink-0 rounded-full bg-warning" />
          <span>{item}</span>
        </li>
      ))}
    </ul>
  );
}
