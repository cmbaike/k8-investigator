import { ChevronRight } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { SeverityBadge } from "@/components/shared/StatusBadge";
import { cn } from "@/lib";
import type { Severity } from "@/types/api";
import { evidenceElementId, useEvidence } from "./EvidenceContext";
import type { EvidenceEntry } from "./evidenceIndex";

function EvidenceDetail({ entry }: { entry: EvidenceEntry }) {
  if (entry.kind === "log") {
    return (
      <p className="text-[13px] text-muted">
        Untrusted application log excerpt. Its text is not part of the report, so it is not shown. A log reference
        shows where an AI claim came from; it does not make the claim true.
      </p>
    );
  }

  if (entry.kind === "unknown") {
    return <p className="text-[13px] text-muted">Details unavailable: this is not a recognised evidence reference.</p>;
  }

  if (entry.citedByFindings.length === 0 && entry.schedulerSignals.length === 0) {
    return (
      <p className="text-[13px] text-muted">
        Details unavailable. This verified observation is cited by an AI hypothesis, but no verified finding describes
        it.
      </p>
    );
  }

  return (
    <div className="space-y-2">
      {entry.schedulerSignals.length > 0 ? (
        <p className="text-[13px]">
          <span className="text-muted">Recorded scheduler signal: </span>
          {entry.schedulerSignals.join("; ")}
        </p>
      ) : null}
      <ul className="space-y-2">
      {entry.citedByFindings.map((finding) => (
        <li key={finding.index} className="space-y-0.5">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={finding.severity as Severity} />
            <span className="text-[13px] font-medium">{finding.title}</span>
          </div>
          <p className="text-[13px] text-muted">{finding.body}</p>
        </li>
      ))}
      </ul>
    </div>
  );
}

function ReferenceRow({ entry }: { entry: EvidenceEntry }) {
  const { openId, toggle } = useEvidence();
  const expanded = openId === entry.id;
  const panelId = `${evidenceElementId(entry.id)}-panel`;
  const findings = entry.citedByFindings.length;
  const hypotheses = entry.citedByHypotheses.length;

  return (
    <li id={evidenceElementId(entry.id)} className="scroll-mt-20">
      <button
        type="button"
        onClick={() => toggle(entry.id)}
        aria-expanded={expanded}
        aria-controls={panelId}
        className="flex w-full cursor-pointer items-center gap-2.5 px-3 py-2 text-left transition-colors hover:bg-surface-2/60"
      >
        <ChevronRight aria-hidden="true" className={cn("size-3.5 shrink-0 text-muted transition-transform", expanded && "rotate-90")} />
        <span className="font-mono text-[13px]">{entry.id}</span>
        <Badge tone={entry.kind === "observation" ? "ok" : entry.kind === "log" ? "warning" : "neutral"}>
          {entry.kind === "observation" ? "Verified observation" : entry.kind === "log" ? "Untrusted log" : "Unrecognised"}
        </Badge>
        <span className="ml-auto text-xs text-muted tabular-nums">
          {findings} finding{findings === 1 ? "" : "s"} · {hypotheses} hypothes{hypotheses === 1 ? "is" : "es"}
        </span>
      </button>
      {expanded ? (
        <div id={panelId} className="space-y-2 px-3 pt-1 pb-3 pl-9">
          <EvidenceDetail entry={entry} />
          {hypotheses > 0 ? (
            <p className="text-xs text-muted">
              Cited by unverified AI hypothesis {entry.citedByHypotheses.map((item) => `#${item.index + 1}`).join(", ")}.
            </p>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

export function EvidencePanel() {
  const { index } = useEvidence();
  const entries = [...index.values()].sort((a, b) => a.id.localeCompare(b.id));

  if (entries.length === 0) {
    return <p className="text-[13px] text-muted">This report cites no evidence references.</p>;
  }

  return (
    <div className="space-y-3">
      <p className="text-[13px] text-muted">
        The API returns reference ids, not raw observations. Each row shows the findings and hypotheses that cite it.
      </p>
      <ul className="divide-y divide-border overflow-hidden rounded-md border border-border" aria-label="Evidence references">
        {entries.map((entry) => (
          <ReferenceRow key={entry.id} entry={entry} />
        ))}
      </ul>
    </div>
  );
}
