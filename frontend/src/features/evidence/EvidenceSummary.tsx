import { ChevronRight } from "lucide-react";
import { useId, useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib";
import { useEvidence } from "./EvidenceContext";
import { evidenceKind } from "./evidenceIndex";

const ROLE_TEXT = {
  cited: "cited by the AI",
  established: "supports the application's statement",
  configuration: "supports the declared configuration",
} as const;

// A compact, clickable label ("Supporting evidence · 7 references") instead of
// a row of raw ids. Expanding it lists the actual references with what the
// backend reported about each: the verified findings that cite it. Nothing is
// invented; a reference no finding describes says so.
export function EvidenceSummary({ ids, label, excludeFinding, hypothesis }: {
  ids: string[];
  label: string;
  /** The finding that owns this label; its own text is not repeated per reference. */
  excludeFinding?: number;
  /** Rank (0-based) of the hypothesis that owns this label, to state each reference's role. */
  hypothesis?: number;
}) {
  const { index, open } = useEvidence();
  const [expanded, setExpanded] = useState(false);
  const panelId = useId();
  const unique = useMemo(() => [...new Set(ids)], [ids]);

  if (unique.length === 0) return null;

  return (
    <div>
      <button
        type="button"
        aria-expanded={expanded}
        aria-controls={panelId}
        onClick={() => setExpanded((value) => !value)}
        className="inline-flex cursor-pointer items-center gap-1 rounded text-xs text-muted transition-colors hover:text-foreground"
      >
        <ChevronRight aria-hidden="true" className={cn("size-3 transition-transform", expanded && "rotate-90")} />
        Supporting evidence · {unique.length} reference{unique.length === 1 ? "" : "s"}
      </button>
      {expanded ? (
        <ul id={panelId} aria-label={label} className="mt-2 divide-y divide-border overflow-hidden rounded-md border border-border">
          {unique.map((id) => {
            const entry = index.get(id);
            const kind = entry?.kind ?? evidenceKind(id);
            const others = (entry?.citedByFindings ?? []).filter((finding) => finding.index !== excludeFinding);
            const roles = hypothesis === undefined ? [] : (entry?.citedByHypotheses ?? []).filter((item) => item.index === hypothesis);

            return (
              <li key={id} className="space-y-1 px-3 py-2">
                <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                  <button
                    type="button"
                    onClick={() => open(id)}
                    aria-label={`Open evidence ${id}`}
                    className="cursor-pointer rounded border border-border px-1.5 py-px font-mono text-[11px] text-foreground transition-colors hover:bg-surface-2"
                  >
                    {id}
                  </button>
                  <Badge tone={kind === "observation" ? "ok" : kind === "log" ? "warning" : "neutral"}>
                    {kind === "observation" ? "Verified observation" : kind === "log" ? "Untrusted log" : "Unrecognised"}
                  </Badge>
                  {roles.length > 0 ? (
                    <span className="text-xs text-muted">{[...new Set(roles.map((item) => ROLE_TEXT[item.role]))].join("; ")}</span>
                  ) : null}
                </div>
                {kind === "log" ? (
                  <p className="text-xs text-muted">Untrusted log excerpt. Its text is not part of the report.</p>
                ) : kind === "unknown" ? (
                  <p className="text-xs text-muted">Details unavailable: not a recognised evidence reference.</p>
                ) : others.length === 0 && (entry?.schedulerSignals.length ?? 0) > 0 ? (
                  <p className="text-xs text-muted">Recorded scheduler signal: {entry?.schedulerSignals.join("; ")}.</p>
                ) : others.length > 0 ? (
                  <ul className="space-y-1">
                    {others.map((finding) => (
                      <li key={finding.index} className="text-xs">
                        <span className="font-medium">{finding.title}</span>
                        <span className="text-muted"> — {finding.body}</span>
                      </li>
                    ))}
                  </ul>
                ) : (entry?.citedByFindings.length ?? 0) > 0 ? (
                  <p className="text-xs text-muted">No other finding describes this reference.</p>
                ) : (
                  <p className="text-xs text-muted">Details unavailable. No verified finding describes this reference.</p>
                )}
              </li>
            );
          })}
        </ul>
      ) : null}
    </div>
  );
}
