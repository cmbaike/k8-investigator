import type { Finding, InvestigationReport } from "@/types/api";

// Presentation grouping only. The vocabulary is the engine's fixed finding-title
// list (see BUCKET_BY_TITLE in scripts/demo_investigation.py). The browser never
// assigns or changes a severity, and a title that is not listed lands in
// "other" and is still shown.
export type Bucket = "discovery" | "symptom" | "config" | "established" | "other";

const BUCKET_BY_TITLE: Record<string, Bucket> = {
  "Pod discovered": "discovery",
  "Pod identified": "discovery",
  "Container logs retrieved": "discovery",
  "Pod phase observed": "symptom",
  "Container readiness observed": "symptom",
  "Container restart count observed": "symptom",
  "Container state observed": "symptom",
  "Container state reason observed": "symptom",
  "Previous container exit code observed": "symptom",
  "Previous container termination reason observed": "symptom",
  "Kubernetes events recorded for the pod": "symptom",
  "Owning workload identified": "config",
  "Container configuration observed": "config",
  "Startup command exits unconditionally (static analysis)": "config",
  "Observed exit code matches the startup command's unconditional exit": "established",
};

export function bucketOf(finding: Finding): Bucket {
  return BUCKET_BY_TITLE[finding.title] ?? "other";
}

export interface DisplayFinding extends Finding {
  index: number;
  body: string;
  resource: string | null;
  tool: string | null;
}

const TOOL_DETAIL = /\s*Observed during tool execution '([^']*)'\./;
const RESOURCE_DETAIL = /\s*Resource: namespace '([^']*)'(?:, pod '([^']*)')?\./;

// The backend appends fixed "Observed during tool execution" and "Resource"
// sentences to a description. They are shown as metadata instead of prose. The
// original text is never altered when the pattern is absent.
export function toDisplayFinding(finding: Finding, index: number): DisplayFinding {
  let body = finding.description;
  let tool: string | null = null;
  let resource: string | null = null;

  const toolMatch = TOOL_DETAIL.exec(body);
  if (toolMatch) {
    tool = toolMatch[1] ?? null;
    body = body.replace(TOOL_DETAIL, "");
  }

  const resourceMatch = RESOURCE_DETAIL.exec(body);
  if (resourceMatch) {
    resource = resourceMatch[2] ? `${resourceMatch[1]}/${resourceMatch[2]}` : (resourceMatch[1] ?? null);
    body = body.replace(RESOURCE_DETAIL, "");
  }

  return { ...finding, index, body: body.trim(), resource, tool };
}

// Display order only: the backend's severity decides what needs attention; the
// browser never assigns or changes one. Ties keep the report's own order.
const ATTENTION_RANK: Record<string, number> = { critical: 0, warning: 1, unknown: 2 };

export function partitionFindings(report: InvestigationReport) {
  const all = report.findings.map(toDisplayFinding);
  const attention = all
    .filter((finding) => finding.severity !== "info")
    .sort((a, b) => (ATTENTION_RANK[a.severity] ?? 9) - (ATTENTION_RANK[b.severity] ?? 9) || a.index - b.index);
  const observations = all.filter((finding) => finding.severity === "info");

  // An observation whose every evidence reference is already cited by a
  // warning-or-higher finding is the raw material of that finding. It stays
  // available, but is grouped instead of repeated alongside it.
  const cited = new Set(attention.flatMap((finding) => finding.evidence.map((item) => item.evidence_id)));
  const isCovered = (finding: DisplayFinding) =>
    finding.evidence.length > 0 && finding.evidence.every((item) => cited.has(item.evidence_id));
  const covered = attention.length > 0 ? observations.filter(isCovered) : [];
  const remaining = observations.filter((finding) => !covered.includes(finding));

  const groups: Record<Bucket, DisplayFinding[]> = {
    discovery: [],
    symptom: [],
    config: [],
    established: [],
    other: [],
  };

  for (const finding of remaining) groups[bucketOf(finding)].push(finding);

  return { all, attention, groups, covered, observationCount: observations.length };
}

const NUMBERED = /^\d+\.\s+\[[a-z]+\]\s/;

// Headline and closing caveat of the engine summary, without the numbered list
// (those findings are shown in full below). Falls back to the whole summary.
export function splitSummary(summary: string): { headline: string[]; closing: string[] } {
  const lines = summary.split("\n").filter((line) => line.trim() !== "");
  const items = lines.flatMap((line, index) => (NUMBERED.test(line) ? [index] : []));

  if (items.length === 0) return { headline: lines, closing: [] };

  const marker = lines.findIndex((line) => line.startsWith("Most significant findings"));
  const headEnd = marker >= 0 ? marker : (items[0] ?? 0);
  const last = items[items.length - 1] ?? 0;

  return { headline: lines.slice(0, headEnd), closing: lines.slice(last + 1) };
}

export const OMISSION_LABELS: Record<string, string> = {
  unattributed_log_claim: "Log claim without attribution",
  reported_without_log_evidence: "Claimed what logs report without a cited log",
  verified_claim: "Presented an interpretation as verified",
  insufficiently_cautious: "Wording was not sufficiently cautious",
  too_long: "Too long",
  contradicts_established_evidence: "Contradicted evidence the application established",
  overstated_absence: "Overstated what an absence proves",
  check_contradicts_evidence: "Suggested check contradicted the evidence",
  duplicate_hypothesis: "Duplicated another hypothesis",
  contradicts_container_state: "Contradicted the container's observed state",
  too_many_references: "Cited more evidence than the limit",
  misattributed_source: "Presented a Kubernetes state as an application log",
  unsupported_specific_claim: "Stated a specific detail no cited evidence supplies",
  inverted_scheduling_terms: "Attributed a taint to a pod or a toleration to a node",
  incorrect_kubernetes_semantics: "Misstated how Kubernetes works",
  unsupported_causal_certainty: "Stated a cause the evidence does not establish",
  remediation_in_check: "Recommended an action instead of a read-only check",
  check_out_of_scope: "Recommended a check outside the investigated resource",
};

export const AI_REASON_LABELS: Record<string, string> = {
  timeout: "The AI stage timed out.",
  provider_error: "The model provider returned an error.",
  malformed_response: "The model returned a malformed response.",
  validation_failed: "The model response failed validation as a whole.",
  no_evidence: "There was no evidence to analyse.",
};

export interface SummaryParts {
  /** The engine's one-line overview, for example the finding and evidence counts. */
  overview: string | null;
  /** Evidence items the engine says it collected, when its overview states a count. */
  evidenceItems: number | null;
  /** What was actually inspected. */
  inspected: string | null;
  /** Remaining statements (scope, caveats) that belong with the limitations. */
  notes: string[];
}

// The engine's findings list is shown in full elsewhere, and its "further
// findings" and "uncertainties" lines only restate counts. Every other line is
// kept: it is either shown in the header or listed under Limitations.
const EVIDENCE_COUNT = /from (\d+) trusted evidence item/;
const RESTATED_COUNT = /^\d+ (?:further finding|uncertaint)/;

export function parseSummary(summary: string): SummaryParts {
  const { headline, closing } = splitSummary(summary);
  const lines = [...headline, ...closing];
  const overview = lines.find((line) => line.startsWith("Investigation of")) ?? null;
  const inspected = lines.find((line) => line.startsWith("Target:")) ?? null;
  const notes = lines.filter(
    (line) =>
      line !== overview &&
      line !== inspected &&
      !line.startsWith("Most significant findings") &&
      !RESTATED_COUNT.test(line),
  );

  const collected = overview ? EVIDENCE_COUNT.exec(overview) : null;

  return {
    overview,
    evidenceItems: collected?.[1] ? Number(collected[1]) : null,
    inspected: inspected ? inspected.replace(/^Target:\s*/, "") : null,
    notes,
  };
}

export interface NextCheck {
  text: string;
  /** "hypothesis": written for the top hypothesis. "report": the report's own first check. */
  source: "hypothesis" | "report";
}

export function nextCheck(report: InvestigationReport): NextCheck | null {
  const top = report.ai_hypotheses[0]?.verification_check?.trim();

  if (top) return { text: top, source: "hypothesis" };

  const first = report.suggested_checks[0]?.trim();

  return first ? { text: first, source: "report" } : null;
}

/** Suggested checks that are not already shown as the recommended next check. */
export function otherChecks(report: InvestigationReport, chosen: NextCheck | null): string[] {
  return report.suggested_checks.filter((check) => check.trim() !== chosen?.text);
}
