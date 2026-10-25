import { ListChecks } from "lucide-react";
import { useCallback, useMemo, useState, type ReactNode } from "react";
import { Callout } from "@/components/shared/Callout";
import { SeverityBadge } from "@/components/shared/StatusBadge";
import { Badge } from "@/components/ui/badge";
import { Disclosure } from "@/components/ui/disclosure";
import { Tabs } from "@/components/ui/tabs";
import { cn } from "@/lib";
import { buildEvidenceIndex } from "@/features/evidence/evidenceIndex";
import { EvidenceProvider, useEvidence } from "@/features/evidence/EvidenceContext";
import { EvidencePanel } from "@/features/evidence/EvidenceTrail";
import { EvidenceSummary } from "@/features/evidence/EvidenceSummary";
import type { Hypothesis, InvestigationReport, Severity } from "@/types/api";
import { buildLimitations, LimitationsPanel } from "./Limitations";
import { NamespaceReport } from "./NamespaceReport";
import {
  nextCheck,
  OMISSION_LABELS,
  otherChecks,
  parseSummary,
  partitionFindings,
  type Bucket,
  type DisplayFinding,
} from "./reportModel";

export const NO_HYPOTHESES_MESSAGE = "No AI hypotheses passed evidence validation for this investigation.";

const SEVERITY_EDGE: Record<Severity, string> = {
  critical: "border-l-critical",
  warning: "border-l-warning",
  unknown: "border-l-muted",
  info: "border-l-border",
};

// About three lines at this width. Longer text is clamped, never cut: the full
// text stays in the page and one click shows it.
const CLAMP_AFTER = 200;

function ExpandableText({ text, label, className, lines = 3 }: { text: string; label: string; className?: string; lines?: 2 | 3 }) {
  const [expanded, setExpanded] = useState(false);
  const long = text.length > (lines === 2 ? 120 : CLAMP_AFTER);

  return (
    <div>
      <p
        className={cn(
          "whitespace-pre-line text-[13px] leading-relaxed text-muted",
          long && !expanded && (lines === 2 ? "line-clamp-2" : "line-clamp-3"),
          className,
        )}
      >
        {text}
      </p>
      {long ? (
        <button
          type="button"
          className="mt-1 cursor-pointer text-xs text-accent hover:underline"
          onClick={() => setExpanded((value) => !value)}
          aria-expanded={expanded}
        >
          {expanded ? "Show less" : label}
        </button>
      ) : null}
    </div>
  );
}

function Resource({ value, title }: { value: string; title: string }) {
  return (
    <span className="block max-w-full truncate font-mono text-xs text-muted" title={title}>
      {value}
    </span>
  );
}

const MAX_ROW_REFS = 2;

// Scheduler constraints the backend classified from validated signals, as
// compact rows. The labels are the backend's own fixed text; no event message
// is read here. Each row links to the observations that establish it.
function ConstraintRows({ finding }: { finding: DisplayFinding }) {
  const { open } = useEvidence();
  const rows = finding.scheduling_constraints ?? [];

  if (rows.length === 0) return null;

  return (
    <div className="space-y-1.5">
      <p className="eyebrow">Reported by the scheduler</p>
      <ul aria-label="Scheduling constraints reported by Kubernetes" className="divide-y divide-border overflow-hidden rounded-md border border-border">
        {rows.map((row) => (
          <li key={row.signal} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5">
            <span aria-hidden="true" className="size-1.5 shrink-0 rounded-full bg-warning" />
            <span className="min-w-0 flex-1 text-[13px] font-medium">{row.label}</span>
            <span className="flex flex-wrap items-center gap-1">
              {row.evidence_ids.slice(0, MAX_ROW_REFS).map((id) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => open(id)}
                  aria-label={`Open evidence ${id} for ${row.label}`}
                  className="cursor-pointer rounded border border-border px-1.5 py-px font-mono text-[11px] text-muted transition-colors hover:bg-surface-2 hover:text-foreground"
                >
                  {id}
                </button>
              ))}
              {row.evidence_ids.length > MAX_ROW_REFS ? (
                <span className="text-[11px] text-muted">+{row.evidence_ids.length - MAX_ROW_REFS}</span>
              ) : null}
            </span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// B. The primary verified operational finding.
function PrimaryFinding({ finding }: { finding: DisplayFinding | undefined }) {
  if (!finding) {
    return (
      <section aria-label="Primary verified finding">
        <Callout tone="info" title="No warning-or-higher verified findings were recorded">
          This does not establish that the workload is healthy. See Limitations.
        </Callout>
      </section>
    );
  }

  const hasRows = (finding.scheduling_constraints ?? []).length > 0;

  return (
    <section
      aria-label="Primary verified finding"
      className={cn("space-y-3 rounded-lg border border-l-[3px] border-border bg-surface px-5 py-4", SEVERITY_EDGE[finding.severity])}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={finding.severity} />
        <p className="eyebrow">Verified finding</p>
      </div>
      <h2 className="text-xl font-semibold leading-tight tracking-tight">{finding.title}</h2>
      {finding.resource ? <Resource value={finding.resource} title="Affected pod" /> : null}
      <ExpandableText text={finding.body} label="Show full finding" lines={hasRows ? 2 : 3} />
      <ConstraintRows finding={finding} />
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <EvidenceSummary ids={finding.evidence.map((item) => item.evidence_id)} label="Evidence for the primary finding" excludeFinding={finding.index} />
        {finding.tool ? <span className="text-xs text-muted">via {finding.tool}</span> : null}
      </div>
    </section>
  );
}

function resourceOf(hypothesis: Hypothesis): string {
  return [hypothesis.resource.namespace, hypothesis.resource.pod, hypothesis.resource.container].filter(Boolean).join(" / ");
}

function LabelledText({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="space-y-0.5">
      <p className="text-xs font-medium text-muted">{label}</p>
      <div className="text-[13px] leading-relaxed">{children}</div>
    </div>
  );
}

// The hypothesis itself: what is claimed, what is not established, what the
// application itself established, and the evidence behind it. Declared
// configuration lives under Findings, not here.
function HypothesisBody({ hypothesis, position, lead }: { hypothesis: Hypothesis; position: number; lead: boolean }) {
  return (
    <div className="space-y-3">
      {hypothesis.reported ? (
        <LabelledText label="Logs report (an unverified claim from untrusted log text)">{hypothesis.reported}</LabelledText>
      ) : null}

      <p className={cn(lead ? "text-[15px] font-medium leading-snug" : "text-[13px]")}>{hypothesis.possible_explanation}</p>

      <LabelledText label="Not yet established">
        <span className="text-muted">{hypothesis.not_yet_verified}</span>
      </LabelledText>

      {hypothesis.independently_established ? (
        <LabelledText label="Established by the application, not the model">{hypothesis.independently_established}</LabelledText>
      ) : null}

      <EvidenceSummary
        ids={[...hypothesis.evidence_refs, ...hypothesis.established_refs, ...hypothesis.configuration_refs]}
        label={`Evidence for hypothesis ${position + 1}`}
        hypothesis={position}
      />

      {lead ? null : hypothesis.verification_check ? (
        <LabelledText label="Suggested read-only check (not performed)">{hypothesis.verification_check}</LabelledText>
      ) : (
        <LabelledText label="Suggested read-only check">
          {`Withheld: ${OMISSION_LABELS[hypothesis.check_withheld_reason ?? ""] ?? "it did not pass validation"}.`}
        </LabelledText>
      )}
    </div>
  );
}

// C. The highest-ranked accepted hypothesis, always marked UNVERIFIED.
function TopHypothesis({ report }: { report: InvestigationReport }) {
  const top = report.ai_hypotheses[0];
  const ai = report.ai_analysis;

  if (!top) {
    return (
      <section aria-label="Top AI hypothesis" className="space-y-1 rounded-lg border border-dashed border-border px-5 py-4">
        <p className="eyebrow">AI diagnostic analysis</p>
        <p className="text-[13px] font-medium">{NO_HYPOTHESES_MESSAGE}</p>
        {ai ? (
          <p className="text-[13px] text-muted">
            {ai.message.replace(/\s*See omission_reasons\.?/, "")}
            {Object.keys(ai.omission_reasons).length > 0 ? " Reasons are listed under Limitations." : ""}
          </p>
        ) : null}
      </section>
    );
  }

  return (
    <section aria-label="Top AI hypothesis" className="space-y-3 rounded-lg border border-dashed border-unverified/50 bg-surface px-5 py-4">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <Badge tone="unverified">UNVERIFIED</Badge>
        <p className="eyebrow">AI hypothesis · ranked #1</p>
        <span className="ml-auto min-w-0 max-w-full">
          <Resource value={resourceOf(top)} title="Affected resource, derived by the application from the cited evidence" />
        </span>
      </div>
      <HypothesisBody hypothesis={top} position={0} lead />
      <p className="text-xs text-muted">Model-generated. Ranked by evidence fit, not probability.</p>
    </section>
  );
}

// The remaining accepted hypotheses, in the application's ranking, collapsed.
function OtherHypotheses({ hypotheses }: { hypotheses: Hypothesis[] }) {
  if (hypotheses.length === 0) return null;

  return (
    <section aria-label="Other AI hypotheses" className="overflow-hidden rounded-lg border border-border bg-surface">
      <Disclosure
        summary={
          <>
            <span className="text-[13px] font-medium">Other hypotheses</span>
            <span className="rounded bg-surface-2 px-1 text-[11px] text-muted tabular-nums">{hypotheses.length}</span>
            <Badge tone="unverified">UNVERIFIED</Badge>
          </>
        }
      >
        <div className="divide-y divide-border overflow-hidden rounded-md border border-border">
          {hypotheses.map((hypothesis, offset) => (
            <Disclosure
              key={offset}
              summary={
                <>
                  <span className="shrink-0 text-xs text-muted tabular-nums">#{offset + 2}</span>
                  <span className="min-w-0 flex-1 truncate text-[13px]">{hypothesis.possible_explanation}</span>
                </>
              }
            >
              <p className="font-mono text-xs text-muted">{resourceOf(hypothesis)}</p>
              <HypothesisBody hypothesis={hypothesis} position={offset + 1} lead={false} />
            </Disclosure>
          ))}
        </div>
      </Disclosure>
    </section>
  );
}

// D. The recommended next diagnostic step. A hypothesis check is the
// application's read-only check; a report check is guidance for a person.
function NextCheck({ report }: { report: InvestigationReport }) {
  const check = nextCheck(report);

  return (
    <section aria-label="Recommended next check" className="space-y-2 rounded-lg border border-border bg-surface-2/50 px-5 py-4">
      <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
        <ListChecks aria-hidden="true" className="size-3.5 text-accent" />
        <p className="eyebrow">Recommended next check</p>
        {check?.source === "hypothesis" ? <Badge>Read-only check · not performed</Badge> : null}
        {check?.source === "report" ? <Badge>Suggested check · for review · not performed</Badge> : null}
      </div>
      {check ? (
        <>
          <p className="text-sm font-medium leading-snug">{check.text}</p>
          <p className="text-xs text-muted">
            {check.source === "hypothesis"
              ? "Written for hypothesis #1."
              : "Guidance for a person to review. This console does not run it."}
          </p>
        </>
      ) : (
        <p className="text-[13px] text-muted">The report contains no suggested checks.</p>
      )}
    </section>
  );
}

const BUCKET_TITLES: Record<Exclude<Bucket, "config">, string> = {
  symptom: "Observed state",
  established: "Corroborated by the application",
  discovery: "Discovery",
  other: "Other observations",
};
const BUCKET_ORDER: Exclude<Bucket, "config">[] = ["symptom", "established", "discovery", "other"];

function FindingRow({ finding }: { finding: DisplayFinding }) {
  return (
    <Disclosure
      summary={
        <>
          <SeverityBadge severity={finding.severity} />
          <span className="min-w-0 flex-1 truncate text-[13px] font-medium">{finding.title}</span>
          {finding.resource ? <span className="hidden max-w-[40%] truncate font-mono text-xs text-muted md:block">{finding.resource}</span> : null}
        </>
      }
    >
      <ExpandableText text={finding.body} label="Show full finding" lines={(finding.scheduling_constraints ?? []).length > 0 ? 2 : 3} />
      <ConstraintRows finding={finding} />
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        <EvidenceSummary ids={finding.evidence.map((item) => item.evidence_id)} label={`Evidence for ${finding.title}`} excludeFinding={finding.index} />
        {finding.tool ? <span className="text-xs text-muted">via {finding.tool}</span> : null}
      </div>
    </Disclosure>
  );
}

function ObservationList({ items }: { items: DisplayFinding[] }) {
  return (
    <ul className="space-y-3">
      {items.map((finding) => (
        <li key={finding.index} className="space-y-1">
          <div className="flex flex-wrap items-baseline gap-x-2">
            <span className="text-[13px] font-medium">{finding.title}</span>
            {finding.resource ? <span className="font-mono text-xs text-muted">{finding.resource}</span> : null}
          </div>
          {finding.body ? <p className="text-[13px] text-muted">{finding.body}</p> : null}
          <EvidenceSummary ids={finding.evidence.map((item) => item.evidence_id)} label={`Evidence for ${finding.title}`} excludeFinding={finding.index} />
        </li>
      ))}
    </ul>
  );
}

function GroupRow({ title, count, children }: { title: string; count: number; children: ReactNode }) {
  return (
    <Disclosure
      summary={
        <>
          <span className="text-[13px]">{title}</span>
          <span className="rounded bg-surface-2 px-1 text-[11px] text-muted tabular-nums">{count}</span>
        </>
      }
    >
      {children}
    </Disclosure>
  );
}

// Hypotheses often carry the same declared-configuration statement. It is
// listed once, with every hypothesis that references it.
function configurationContexts(report: InvestigationReport) {
  const byText = new Map<string, { text: string; positions: number[]; refs: string[] }>();

  report.ai_hypotheses.forEach((hypothesis, position) => {
    const text = hypothesis.configuration_context?.trim();

    if (!text) return;

    const entry = byText.get(text) ?? { text, positions: [], refs: [] };

    entry.positions.push(position);
    entry.refs.push(...hypothesis.configuration_refs);
    byText.set(text, entry);
  });

  return [...byText.values()];
}

function findingsCount(report: InvestigationReport, complete = false): number {
  const { attention, observationCount } = partitionFindings(report);
  const shown = complete ? attention.length : Math.max(0, attention.length - 1);

  return shown + observationCount + configurationContexts(report).length;
}

// Findings tab: everything except the primary finding, each observation once.
// A namespace-wide report has no single primary finding, so the tab keeps all of them.
function FindingsPanel({ report, complete = false }: { report: InvestigationReport; complete?: boolean }) {
  const { attention, groups, covered } = useMemo(() => partitionFindings(report), [report]);
  const checks = complete ? report.suggested_checks : otherChecks(report, nextCheck(report));
  const further = complete ? attention : attention.slice(1);
  const buckets = BUCKET_ORDER.filter((bucket) => groups[bucket].length > 0);
  const contexts = configurationContexts(report);
  const configuration = groups.config.length + contexts.length;
  const empty = further.length === 0 && covered.length === 0 && buckets.length === 0 && configuration === 0 && checks.length === 0;

  if (empty) {
    return (
      <p className="text-[13px] text-muted">
        {complete ? "No findings were recorded." : "No further findings. The primary finding above is the only one recorded."}
      </p>
    );
  }

  return (
    <div className="space-y-3">
      <div className="divide-y divide-border overflow-hidden rounded-md border border-border">
        {further.map((finding) => (
          <FindingRow key={finding.index} finding={finding} />
        ))}
        {covered.length > 0 ? (
          <GroupRow title="Underlying observations (cited by the findings above)" count={covered.length}>
            <ObservationList items={covered} />
          </GroupRow>
        ) : null}
        {buckets.map((bucket) => (
          <GroupRow key={bucket} title={BUCKET_TITLES[bucket]} count={groups[bucket].length}>
            <ObservationList items={groups[bucket]} />
          </GroupRow>
        ))}
        {configuration > 0 ? (
          <GroupRow title="Configuration observations" count={configuration}>
            <ObservationList items={groups.config} />
            {contexts.map((context) => (
              <div key={context.text} className="space-y-1">
                <p className="text-xs text-muted">
                  Written by the application from verified evidence; referenced by unverified{" "}
                  {context.positions.length === 1 ? "hypothesis" : "hypotheses"} {context.positions.map((position) => `#${position + 1}`).join(", ")}.
                </p>
                <p className="text-[13px]">{context.text}</p>
                <EvidenceSummary ids={context.refs} label={`Configuration evidence for ${context.text.slice(0, 40)}`} />
              </div>
            ))}
          </GroupRow>
        ) : null}
        {checks.length > 0 ? (
          <GroupRow title={complete ? "Suggested checks (not performed)" : "Other suggested checks (not performed)"} count={checks.length}>
            <ol className="list-decimal space-y-1 pl-4 text-[13px]">
              {checks.map((check, position) => (
                <li key={position}>{check}</li>
              ))}
            </ol>
          </GroupRow>
        ) : null}
      </div>
    </div>
  );
}

const SEVERITY_ORDER: { severity: Severity; label: string; tone: string }[] = [
  { severity: "critical", label: "critical", tone: "text-critical" },
  { severity: "warning", label: "warning", tone: "text-warning" },
  { severity: "unknown", label: "unknown", tone: "text-muted" },
  { severity: "info", label: "info", tone: "text-muted" },
];

// Compact metadata in place of the engine's summary paragraph. Every number is
// counted from the report itself, except the evidence total, which is the
// engine's own statement of how many items it collected (shown only when the
// summary states one).
function ReportMeta({ report, evidenceItems, inspected }: { report: InvestigationReport; evidenceItems: number | null; inspected: string | null }) {
  const counts = SEVERITY_ORDER.map((entry) => ({ ...entry, count: report.findings.filter((finding) => finding.severity === entry.severity).length })).filter(
    (entry) => entry.count > 0,
  );
  const hypotheses = report.ai_hypotheses.length;

  return (
    <dl className="flex flex-wrap gap-x-5 gap-y-1 text-[13px] text-muted">
      <div className="flex gap-1.5">
        <dt>Findings</dt>
        <dd className="text-foreground tabular-nums">
          {counts.length === 0
            ? "none recorded"
            : counts.map((entry, position) => (
                <span key={entry.severity}>
                  {position > 0 ? " · " : ""}
                  <span className={entry.tone}>{entry.count} {entry.label}</span>
                </span>
              ))}
        </dd>
      </div>
      {evidenceItems !== null ? (
        <div className="flex gap-1.5">
          <dt>Evidence collected</dt>
          <dd className="text-foreground tabular-nums">{evidenceItems}</dd>
        </div>
      ) : null}
      <div className="flex gap-1.5">
        <dt>AI hypotheses</dt>
        <dd className="text-foreground tabular-nums">{hypotheses === 0 ? "none accepted" : `${hypotheses} unverified`}</dd>
      </div>
      {inspected ? (
        <div className="flex basis-full gap-1.5">
          <dt className="shrink-0">Inspected</dt>
          <dd className="min-w-0 text-foreground">{inspected}</dd>
        </div>
      ) : null}
    </dl>
  );
}

function UngroupedNamespaceReport({ report }: { report: InvestigationReport }) {
  const { attention } = partitionFindings(report);

  return (
    <div className="space-y-3">
      <p className="text-[13px] text-muted">
        This report was stored without resource groups. Findings and hypotheses are listed separately, not as one diagnostic sequence.
      </p>
      {attention.length > 0 ? (
        <div className="divide-y divide-border overflow-hidden rounded-md border border-border">
          {attention.map((finding) => (
            <FindingRow key={finding.index} finding={finding} />
          ))}
        </div>
      ) : (
        <p className="text-[13px] text-muted">No abnormal condition was recorded.</p>
      )}
      {report.ai_hypotheses.map((hypothesis, index) => (
        <section key={index} aria-label={`AI hypothesis ${index + 1}`} className="space-y-2 rounded-lg border border-dashed border-unverified/50 bg-surface px-5 py-4">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone="unverified">UNVERIFIED</Badge>
            <p className="font-mono text-xs text-muted">{resourceOf(hypothesis)}</p>
          </div>
          <HypothesisBody hypothesis={hypothesis} position={index} lead={false} />
        </section>
      ))}
      {report.suggested_checks.length > 0 ? (
        <section aria-label="Suggested checks" className="space-y-2 rounded-lg border border-border px-5 py-4">
          <p className="eyebrow">Suggested checks</p>
          <p className="text-xs text-muted">Not tied to one finding. This console does not run them.</p>
          <ol className="list-decimal space-y-1 pl-4 text-[13px]">
            {report.suggested_checks.map((check, index) => (
              <li key={index}>{check}</li>
            ))}
          </ol>
        </section>
      ) : null}
    </div>
  );
}

export function ReportView({ report, rejectedProposals, stopReason, auditPanel, auditCount, scopeMode = "workload" }: {
  report: InvestigationReport;
  rejectedProposals: number;
  stopReason: string | null;
  auditPanel: ReactNode;
  auditCount: number | null;
  scopeMode?: "workload" | "namespace" | "unspecified";
}) {
  const index = useMemo(() => buildEvidenceIndex(report), [report]);
  const { attention } = useMemo(() => partitionFindings(report), [report]);
  const summaryParts = useMemo(() => parseSummary(report.summary), [report.summary]);
  const limitations = useMemo(() => buildLimitations(report, rejectedProposals, stopReason), [report, rejectedProposals, stopReason]);
  const [tab, setTab] = useState("findings");
  const reveal = useCallback(() => setTab("evidence"), []);
  const namespaceWide = scopeMode === "namespace";

  return (
    <EvidenceProvider index={index} onReveal={reveal}>
      <ReportMeta report={report} evidenceItems={summaryParts.evidenceItems} inspected={summaryParts.inspected} />

      {namespaceWide ? (
        report.namespace_diagnostic ? (
          <NamespaceReport report={report} />
        ) : (
          <UngroupedNamespaceReport report={report} />
        )
      ) : (
        <>
          <div className="space-y-3">
            <PrimaryFinding finding={attention[0]} />
            <TopHypothesis report={report} />
            <OtherHypotheses hypotheses={report.ai_hypotheses.slice(1)} />
          </div>
          <NextCheck report={report} />
        </>
      )}

      <Tabs
        label="Technical details"
        value={tab}
        onChange={setTab}
        items={[
          { id: "findings", label: "Findings", count: findingsCount(report, namespaceWide), panel: <FindingsPanel report={report} complete={namespaceWide} /> },
          { id: "evidence", label: "Evidence", count: index.size, panel: <EvidencePanel /> },
          { id: "audit", label: "Audit", count: auditCount, panel: auditPanel },
          { id: "limitations", label: "Limitations", count: limitations.length, attention: true, panel: <LimitationsPanel items={limitations} /> },
        ]}
      />
    </EvidenceProvider>
  );
}
