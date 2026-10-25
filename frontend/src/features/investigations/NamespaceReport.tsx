import { Badge } from "@/components/ui/badge";
import { Disclosure } from "@/components/ui/disclosure";
import { SeverityBadge } from "@/components/shared/StatusBadge";
import { EvidenceSummary } from "@/features/evidence/EvidenceSummary";
import type {
  DiagnosticCheck,
  DiagnosticResource,
  Hypothesis,
  InvestigationReport,
  Severity,
} from "@/types/api";

const NO_HYPOTHESIS = "No accepted AI hypothesis for this resource.";
const NO_CONDITION = "No abnormal condition was verified for this resource.";
const NO_CHECK = "No recommended check is associated with this resource.";

const RANK: Record<string, number> = { critical: 0, warning: 1, unknown: 2, info: 3 };

function worst(report: InvestigationReport, resource: DiagnosticResource): Severity | null {
  const ranks = resource.findings
    .map((item) => report.findings[item.index]?.severity)
    .filter((severity): severity is Severity => severity !== undefined && severity !== "info");

  ranks.sort((a, b) => (RANK[a] ?? 9) - (RANK[b] ?? 9));

  return ranks[0] ?? null;
}

function CheckLine({ check }: { check: DiagnosticCheck }) {
  return (
    <li className="space-y-1">
      <p className="text-[13px]">{check.text}</p>
      <Badge>{check.source === "hypothesis" ? "Read-only check · not performed" : "Suggested check · for review · not performed"}</Badge>
    </li>
  );
}

function isPlaced(
  item: { index: number; hypothesis: Hypothesis | undefined },
): item is { index: number; hypothesis: Hypothesis } {
  return item.hypothesis !== undefined;
}

function HypothesisBlock({ hypothesis, position }: { hypothesis: Hypothesis; position: number }) {
  const where = [hypothesis.resource.pod, hypothesis.resource.container].filter(Boolean).join(" / ");

  return (
    <div className="space-y-1 rounded-md border border-dashed border-unverified/40 px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="unverified">UNVERIFIED</Badge>
        <span className="text-xs text-muted">Hypothesis #{position + 1}</span>
        {where ? <span className="font-mono text-xs text-muted">{where}</span> : null}
      </div>
      <p className="text-[13px]">{hypothesis.possible_explanation}</p>
      <p className="text-xs text-muted">{hypothesis.not_yet_verified}</p>
    </div>
  );
}

function PodSection({
  report,
  resource,
  pod,
}: {
  report: InvestigationReport;
  resource: DiagnosticResource;
  pod: string | null;
}) {
  const findings = resource.findings.filter((item) => item.pod === pod);
  const abnormal = findings.filter((item) => report.findings[item.index]?.severity !== "info");
  const other = findings.filter((item) => report.findings[item.index]?.severity === "info");
  const hypotheses = resource.hypothesis_indexes
    .map((index) => ({ index, hypothesis: report.ai_hypotheses[index] }))
    .filter(isPlaced)
    .filter((item) => (pod === null ? item.hypothesis.resource.pod == null : item.hypothesis.resource.pod === pod));
  const checks = resource.checks.filter((check) => (pod === null ? check.pod == null : check.pod === pod));

  if (abnormal.length === 0 && other.length === 0 && hypotheses.length === 0 && checks.length === 0) {
    return null;
  }

  return (
    <div className="space-y-3">
      {pod && resource.kind !== "Pod" ? <p className="font-mono text-xs text-muted">Pod {pod}</p> : null}
      {pod !== null && abnormal.length === 0 ? (
        <p className="text-[13px] text-muted">{NO_CONDITION}</p>
      ) : null}
      {abnormal.length > 0 ? (
        <ul className="space-y-3">
          {abnormal.map((item) => {
            const finding = report.findings[item.index];

            if (!finding) return null;

            return (
              <li key={item.index} className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <span className="text-[13px] font-medium">{finding.title}</span>
                </div>
                <p className="text-[13px] text-muted">{finding.description}</p>
                <EvidenceSummary
                  ids={finding.evidence.map((reference) => reference.evidence_id)}
                  label={`Evidence for ${finding.title}`}
                  excludeFinding={item.index}
                />
              </li>
            );
          })}
        </ul>
      ) : null}
      {pod !== null && hypotheses.length === 0 ? (
        <p className="text-[13px]">{NO_HYPOTHESIS}</p>
      ) : (
        hypotheses.map(({ index, hypothesis }) => (
          <HypothesisBlock key={index} hypothesis={hypothesis} position={index} />
        ))
      )}
      {pod !== null && checks.length === 0 ? (
        <p className="text-[13px] text-muted">{NO_CHECK}</p>
      ) : checks.length > 0 ? (
        <ul className="space-y-2">
          {checks.map((check, index) => (
            <CheckLine key={index} check={check} />
          ))}
        </ul>
      ) : null}
      {other.length > 0 ? (
        <Disclosure summary={<span className="text-[13px]">Other observations</span>}>
          <ul className="space-y-2">
            {other.map((item) => {
              const finding = report.findings[item.index];

              if (!finding) return null;

              return (
                <li key={item.index} className="text-[13px] text-muted">
                  {finding.title}
                </li>
              );
            })}
          </ul>
        </Disclosure>
      ) : null}
    </div>
  );
}

function coverageSummary(resource: DiagnosticResource, title: string | undefined): string {
  if (resource.coverage === "unknown") return "Health unknown";
  if (resource.coverage === "failed") return "Inspection did not succeed";

  return title ?? "No abnormal condition";
}

function ResourceCard({ report, resource }: { report: InvestigationReport; resource: DiagnosticResource }) {
  const severity = worst(report, resource);
  const abnormal = resource.findings
    .map((item) => report.findings[item.index])
    .filter((finding) => finding && finding.severity !== "info");
  const label = `${resource.kind} ${resource.name}`;
  const coverage = resource.coverage ?? "established";
  const showDeepNote =
    coverage === "established" && abnormal.length > 0 && resource.deeply_investigated === false;

  return (
    <section aria-label={label} className="overflow-hidden rounded-lg border border-border bg-surface">
      <Disclosure
        summary={
          <>
            <span className="truncate text-[13px] font-medium">{label}</span>
            {severity ? <SeverityBadge severity={severity} /> : null}
            <span className="hidden min-w-0 flex-1 truncate text-xs text-muted sm:block">
              {coverageSummary(resource, abnormal[0]?.title)}
            </span>
            {resource.hypothesis_indexes.length === 0 ? (
              <span className="shrink-0 text-xs text-muted">No accepted hypothesis</span>
            ) : (
              <Badge tone="unverified">
                {resource.hypothesis_indexes.length} unverified
              </Badge>
            )}
          </>
        }
      >
        <div className="space-y-4">
          {resource.ownership === "unresolved" ? (
            <p className="text-[13px] text-muted">
              The controlling workload was not verified, so this pod is shown on its own.
            </p>
          ) : null}
          {resource.ownership === "verified" && resource.kind === "Pod" ? (
            <p className="text-[13px] text-muted">This pod has no controlling workload.</p>
          ) : null}
          {coverage === "unknown" ? (
            <p className="text-[13px]">
              This resource was listed and was not health-inspected. Its health is unknown, not healthy.
            </p>
          ) : null}
          {coverage === "failed" ? (
            <p className="text-[13px]">
              A health inspection was attempted and did not succeed. That is not a healthy result.
            </p>
          ) : null}
          {showDeepNote ? (
            <p className="text-[13px] text-muted">
              Health-inspected, but not deeply investigated. Logs, events, and workload configuration were not read for this resource.
            </p>
          ) : null}
          <PodSection report={report} resource={resource} pod={null} />
          {resource.pods.map((pod) => (
            <PodSection key={pod} report={report} resource={resource} pod={pod} />
          ))}
        </div>
      </Disclosure>
    </section>
  );
}

function CoverageStatus({
  diagnostic,
}: {
  diagnostic: NonNullable<InvestigationReport["namespace_diagnostic"]>;
}) {
  const countsIncomplete = diagnostic.inspected_pods < diagnostic.listed_pods;
  const incomplete = diagnostic.assessment_complete === false || countsIncomplete;
  const complete = diagnostic.assessment_complete === true && !countsIncomplete;
  const uninspected = diagnostic.uninspected_pods ?? 0;
  const unsuccessful = diagnostic.unsuccessful_pods ?? 0;

  return (
    <>
      {complete ? (
        <p className="text-[13px] text-muted">
          Health inspection covered every listed pod. That is not a statement that every workload is healthy.
        </p>
      ) : null}
      {incomplete ? (
        <p className="text-[13px]">
          Health assessment is incomplete. An investigation can finish while listed pods were not health-inspected.
        </p>
      ) : null}
      {uninspected > 0 ? (
        <p className="text-[13px]">
          {uninspected} listed pod(s) were not health-inspected. Their health is unknown, not healthy.
        </p>
      ) : null}
      {unsuccessful > 0 ? (
        <p className="text-[13px]">
          {unsuccessful} health inspection(s) did not succeed. That is not a healthy result.
        </p>
      ) : null}
      {diagnostic.listing_truncated ? (
        <p className="text-[13px]">
          The pod list was longer than one API page. Pods beyond that page were not discovered and are unknown.
        </p>
      ) : null}
    </>
  );
}

export function NamespaceReport({ report }: { report: InvestigationReport }) {
  const diagnostic = report.namespace_diagnostic;

  if (!diagnostic) return null;

  const sharedHypotheses = diagnostic.shared_hypothesis_indexes
    .map((index) => ({ index, hypothesis: report.ai_hypotheses[index] }))
    .filter(isPlaced);
  const shared = diagnostic.shared_findings.length + sharedHypotheses.length + diagnostic.shared_checks.length;

  return (
    <div className="space-y-3">
      <section aria-label="Namespace summary" className="space-y-1">
        <p className="eyebrow">Namespace summary</p>
        <p className="text-[13px] text-muted">
          Observed resource coverage: {diagnostic.inspected_pods} inspected of {diagnostic.listed_pods} listed.
        </p>
        <CoverageStatus diagnostic={diagnostic} />
      </section>
      {diagnostic.resources.length === 0 ? (
        <p className="text-[13px] text-muted">No affected workload was established from the verified evidence.</p>
      ) : (
        <div className="space-y-2" aria-label="Affected workloads">
          {diagnostic.resources.map((resource) => (
            <ResourceCard key={`${resource.kind}/${resource.name}`} report={report} resource={resource} />
          ))}
        </div>
      )}
      {shared > 0 ? (
        <section aria-label="Namespace-level evidence" className="space-y-3 rounded-lg border border-border px-5 py-4">
          <p className="eyebrow">Namespace-level</p>
          <p className="text-[13px] text-muted">Not attributed to one workload.</p>
          <ul className="space-y-2">
            {diagnostic.shared_findings.map((item) => {
              const finding = report.findings[item.index];

              if (!finding) return null;

              return (
                <li key={item.index} className="text-[13px]">
                  <span className="font-medium">{finding.title}</span>
                </li>
              );
            })}
          </ul>
          {sharedHypotheses.map(({ index, hypothesis }) => (
            <HypothesisBlock key={index} hypothesis={hypothesis} position={index} />
          ))}
          {diagnostic.shared_checks.length > 0 ? (
            <ul className="space-y-2">
              {diagnostic.shared_checks.map((check, index) => (
                <CheckLine key={index} check={check} />
              ))}
            </ul>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}
