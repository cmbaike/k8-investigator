import type { InvestigationReport } from "@/types/api";
import { toDisplayFinding } from "@/features/investigations/reportModel";

export type EvidenceKind = "observation" | "log" | "unknown";

export interface EvidenceEntry {
  id: string;
  kind: EvidenceKind;
  citedByFindings: { index: number; title: string; severity: string; body: string }[];
  citedByHypotheses: { index: number; role: "cited" | "established" | "configuration" }[];
  /** Scheduler constraints (backend-minted labels) this observation is the recorded signal for. */
  schedulerSignals: string[];
}

export function evidenceKind(id: string): EvidenceKind {
  if (/^ev-\d{4}$/.test(id)) return "observation";
  if (/^log-\d{4}$/.test(id)) return "log";

  return "unknown";
}

// Everything the report response can say about a reference: which verified
// findings and which hypotheses cite it. The API has no endpoint that returns
// the underlying observation, so nothing else is ever shown.
export function buildEvidenceIndex(report: InvestigationReport): Map<string, EvidenceEntry> {
  const index = new Map<string, EvidenceEntry>();

  const entry = (id: string): EvidenceEntry => {
    let found = index.get(id);

    if (!found) {
      found = { id, kind: evidenceKind(id), citedByFindings: [], citedByHypotheses: [], schedulerSignals: [] };
      index.set(id, found);
    }

    return found;
  };

  report.findings.forEach((finding, position) => {
    const display = toDisplayFinding(finding, position);

    for (const { evidence_id } of finding.evidence) {
      entry(evidence_id).citedByFindings.push({
        index: position,
        title: finding.title,
        severity: finding.severity,
        body: display.body,
      });
    }
  });

  for (const finding of report.findings) {
    for (const constraint of finding.scheduling_constraints ?? []) {
      for (const id of constraint.evidence_ids) {
        const found = entry(id);

        if (!found.schedulerSignals.includes(constraint.label)) found.schedulerSignals.push(constraint.label);
      }
    }
  }

  report.ai_hypotheses.forEach((hypothesis, position) => {
    const add = (ids: string[], role: "cited" | "established" | "configuration") => {
      for (const id of ids) entry(id).citedByHypotheses.push({ index: position, role });
    };

    add(hypothesis.evidence_refs, "cited");
    add(hypothesis.established_refs, "established");
    add(hypothesis.configuration_refs, "configuration");
  });

  return index;
}
