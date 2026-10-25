import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ID, audit, report, summary } from "@/test/fixtures";
import { installMockApi, renderApp, resetApp, type MockApi } from "@/test/mockApi";
import type { InvestigationReport, NamespaceDiagnostic } from "@/types/api";
import { NO_HYPOTHESES_MESSAGE } from "./ReportView";

const primary = () => screen.findByRole("region", { name: "Primary verified finding" });
const topHypothesis = () => screen.getByRole("region", { name: "Top AI hypothesis" });
const nextCheckRegion = () => screen.getByRole("region", { name: "Recommended next check" });
const openTab = (user: ReturnType<typeof userEvent.setup>, name: string) =>
  user.click(screen.getByRole("tab", { name: new RegExp(`^${name}`) }));
const panel = () => screen.getByRole("tabpanel");
const expandEvidence = (user: ReturnType<typeof userEvent.setup>, region: HTMLElement) =>
  user.click(within(region).getByRole("button", { name: /^Supporting evidence/ }));

let api: MockApi;
const route = `/investigations/${ID}`;

function completed(r: InvestigationReport = report()) {
  api.on(`GET /api/investigations/${ID}/summary`, { body: summary() });
  api.on(`GET /api/investigations/${ID}/report`, { body: r });
  api.on(`GET /api/investigations/${ID}/audit`, { body: audit() });
}

beforeEach(() => {
  api = installMockApi();
  api.on("GET /api/health", { body: { status: "ok", database: true } });
});
afterEach(() => {
  resetApp();
  vi.useRealTimers();
});



describe("page structure", () => {
  it("shows a compact header: workload, kind, namespace, status, duration and scope", async () => {
    completed();
    renderApp(route, api);

    expect(await screen.findByRole("heading", { level: 1, name: "bad-readiness" })).toBeInTheDocument();
    expect(screen.getByText("Deployment")).toBeInTheDocument();
    expect(screen.getByText("ai-ops-demo", { selector: "dd" })).toBeInTheDocument();
    expect(screen.getAllByText("Completed").length).toBeGreaterThan(0);
    expect(screen.getByText("7.0 s")).toBeInTheDocument();
    expect(screen.getByText(/one workload · read-only/)).toBeInTheDocument();
  });

  it("keeps the full id and secondary metadata behind one disclosure", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    expect(screen.queryByText(ID)).not.toBeInTheDocument();
    expect(screen.queryByText("provider_finished")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Details" }));

    expect(screen.getByText(ID)).toBeInTheDocument();
    expect(screen.getByText("provider_finished")).toBeInTheDocument();
    expect(screen.getByText("6 read-only calls")).toBeInTheDocument();
    expect(screen.getByText("Investigate deployment/bad-readiness. Why is this workload unhealthy?")).toBeInTheDocument();
  });

  it("labels a namespace-wide investigation as such", async () => {
    api.on(`GET /api/investigations/${ID}/summary`, { body: summary({ scope: { mode: "namespace", kind: null, name: null } }) });
    api.on(`GET /api/investigations/${ID}/report`, { body: report() });
    api.on(`GET /api/investigations/${ID}/audit`, { body: audit() });
    renderApp(route, api);

    expect(await screen.findByRole("heading", { level: 1, name: "Whole namespace" })).toBeInTheDocument();
    expect(screen.getByText("Namespace-wide")).toBeInTheDocument();
    expect(screen.getByText(/whole namespace · read-only/)).toBeInTheDocument();
  });

  it("orders the page: finding, top hypothesis, next check, technical details", async () => {
    completed();
    renderApp(route, api);

    await primary();
    const order = [
      screen.getByRole("region", { name: "Primary verified finding" }),
      topHypothesis(),
      nextCheckRegion(),
      screen.getByRole("tablist", { name: "Technical details" }),
    ];

    for (let i = 1; i < order.length; i += 1) {
      expect(order[i - 1]!.compareDocumentPosition(order[i]!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    }
  });

  it("shows compact metadata and what was inspected, and keeps the scope caveat under Limitations", async () => {
    completed(
      report({
        summary:
          "Investigation of namespace 'ai-ops-demo': 3 verified finding(s) (1 critical, 2 info) from 9 trusted evidence item(s).\nScope: only namespace 'ai-ops-demo'. This is not an assessment of the rest of the cluster.\nTarget: Deployment 'bad-readiness', verified through Kubernetes owner references. Inspected only its 1 pod(s): 'a'. The other 1 pod(s) listed in the namespace were not inspected.\nMost significant findings:\n1. [critical] Container is running but not ready\n2 further finding(s) are listed in the report.\n1 uncertainty(ies) are recorded.",
      }),
    );
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    // The summary paragraph is replaced by compact metadata counted from the report.
    expect(screen.queryByText(/Investigation of namespace/)).not.toBeInTheDocument();
    const meta = screen.getByText("Findings", { selector: "dt" }).closest("dl") as HTMLElement;
    expect(within(meta).getByText("Findings").nextElementSibling).toHaveTextContent("1 critical · 2 info");
    expect(within(meta).getByText("Evidence collected").nextElementSibling).toHaveTextContent("9");
    expect(within(meta).getByText("AI hypotheses").nextElementSibling).toHaveTextContent("1 unverified");
    // Partial coverage is stated up front, not only in a tab.
    expect(within(meta).getByText("Inspected").nextElementSibling).toHaveTextContent(
      /Deployment 'bad-readiness'.*The other 1 pod\(s\) listed in the namespace were not inspected/,
    );
    expect(screen.queryByText(/2 further finding/)).not.toBeInTheDocument();
    expect(screen.queryByText(/\[critical\]/)).not.toBeInTheDocument();

    await openTab(user, "Limitations");
    expect(screen.getByText(/not an assessment of the rest of the cluster/)).toBeInTheDocument();
  });
});

describe("primary finding", () => {
  it("shows severity, title, affected pod and the explanation of the most severe finding", async () => {
    completed();
    renderApp(route, api);

    const region = await primary();

    expect(within(region).getByRole("heading", { level: 2, name: "Container is running but not ready" })).toBeInTheDocument();
    expect(within(region).getByText("Critical")).toBeInTheDocument();
    expect(within(region).getByText("ai-ops-demo/bad-readiness-abc")).toBeInTheDocument();
    expect(within(region).getByText(/Container 'app' is running but Kubernetes reports it is not ready\./)).toBeInTheDocument();
    expect(within(region).getByText("via k8s.describe_pod")).toBeInTheDocument();
    expect(within(region).queryByText("UNVERIFIED")).not.toBeInTheDocument();
    expect(within(region).queryByText(/Observed during tool execution/)).not.toBeInTheDocument();
    // Evidence is a compact label, not a row of raw ids.
    expect(within(region).getByRole("button", { name: "Supporting evidence · 2 references" })).toBeInTheDocument();
    expect(within(region).queryByText("ev-0005")).not.toBeInTheDocument();
  });

  it("shows at most three lines by default and expands to the full finding", async () => {
    const long = `${"The container restarted repeatedly. ".repeat(20)}END-OF-TEXT`;
    completed(report({ findings: [{ title: "Container is crash-looping", description: long, severity: "critical", evidence: [{ evidence_id: "ev-0001" }] }], ai_hypotheses: [] }));
    const user = userEvent.setup();
    renderApp(route, api);

    const region = await primary();
    const text = within(region).getByText(/END-OF-TEXT/);

    expect(text).toHaveClass("line-clamp-3");
    const button = within(region).getByRole("button", { name: "Show full finding" });
    expect(button).toHaveAttribute("aria-expanded", "false");

    await user.click(button);
    expect(text).not.toHaveClass("line-clamp-3");
    expect(within(region).getByRole("button", { name: "Show less" })).toHaveAttribute("aria-expanded", "true");
  });

  it("does not clamp a short finding or offer to expand it", async () => {
    completed();
    renderApp(route, api);

    const region = await primary();

    expect(within(region).queryByRole("button", { name: "Show full finding" })).not.toBeInTheDocument();
  });

  it("promotes the most severe finding regardless of report order and keeps the others under Findings", async () => {
    completed(
      report({
        findings: [
          { title: "Restart count is elevated", description: "It has restarted 3 times.", severity: "warning", evidence: [{ evidence_id: "ev-0010" }] },
          { title: "Container is crash-looping", description: "Back-off restarting failed container.", severity: "critical", evidence: [{ evidence_id: "ev-0011" }] },
          { title: "Image pull is slow", description: "Pull took 40 seconds.", severity: "warning", evidence: [{ evidence_id: "ev-0012" }] },
        ],
        ai_hypotheses: [],
      }),
    );
    const user = userEvent.setup();
    renderApp(route, api);

    const region = await primary();
    expect(within(region).getByRole("heading", { name: "Container is crash-looping" })).toBeInTheDocument();
    expect(within(region).queryByText("Restart count is elevated")).not.toBeInTheDocument();

    // Findings is the default tab. The primary finding is not repeated in it.
    expect(screen.getByRole("tab", { name: "Findings 2" })).toHaveAttribute("aria-selected", "true");
    expect(within(panel()).queryByText("Container is crash-looping")).not.toBeInTheDocument();
    await user.click(within(panel()).getByRole("button", { name: /Restart count is elevated/ }));
    expect(within(panel()).getByText("It has restarted 3 times.")).toBeInTheDocument();
    expect(within(panel()).getByRole("button", { name: /Image pull is slow/ })).toBeInTheDocument();
  });

  it("does not imply health when there are no warning-or-higher findings", async () => {
    completed(report({ findings: [{ title: "Pod phase observed", description: "Phase Running.", severity: "info", evidence: [{ evidence_id: "ev-0003" }] }], ai_hypotheses: [] }));
    renderApp(route, api);

    const region = await primary();

    expect(within(region).getByText("No warning-or-higher verified findings were recorded")).toBeInTheDocument();
    expect(within(region).getByText(/does not establish that the workload is healthy/i)).toBeInTheDocument();
    // The informational observation is still reachable.
    expect(within(panel()).getByRole("button", { name: /Observed state/ })).toBeInTheDocument();
  });

  it("opens supporting evidence to the references and the backend's own observations, never invented ones", async () => {
    completed(
      report({
        findings: [
          { title: "Container is running but not ready", description: "Container 'app' is not ready.", severity: "critical", evidence: [{ evidence_id: "ev-0005" }, { evidence_id: "ev-0006" }] },
          { title: "Container readiness observed", description: "Readiness is false for 'app'.", severity: "info", evidence: [{ evidence_id: "ev-0005" }] },
        ],
        ai_hypotheses: [],
      }),
    );
    const user = userEvent.setup();
    renderApp(route, api);

    const region = await primary();
    await expandEvidence(user, region);

    const list = within(region).getByRole("list", { name: "Evidence for the primary finding" });
    const items = [...list.children] as HTMLElement[];

    expect(items).toHaveLength(2);
    // ev-0005: described by the observation finding that cites it.
    expect(within(items[0]!).getByRole("button", { name: "Open evidence ev-0005" })).toBeInTheDocument();
    expect(within(items[0]!).getByText("Container readiness observed")).toBeInTheDocument();
    expect(within(items[0]!).getByText(/Readiness is false for 'app'\./)).toBeInTheDocument();
    // ev-0006: only the primary finding cites it, so nothing more is claimed.
    expect(within(items[1]!).getByText("No other finding describes this reference.")).toBeInTheDocument();
    expect(within(items[1]!).queryByText(/Container 'app' is not ready/)).not.toBeInTheDocument();
  });
});

describe("AI diagnostic analysis", () => {
  it("marks the top hypothesis UNVERIFIED, directly below the primary finding", async () => {
    completed();
    renderApp(route, api);

    const finding = await primary();
    const region = topHypothesis();

    expect(finding.compareDocumentPosition(region) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(within(region).getByText("UNVERIFIED")).toBeInTheDocument();
    expect(within(region).getByText(/ranked #1/)).toBeInTheDocument();
    expect(within(region).getByText(/readiness probe may be failing/)).toBeInTheDocument();
    expect(within(region).getByText("Not yet established")).toBeInTheDocument();
    expect(within(region).getByText(/It has not been verified whether the probe path exists/)).toBeInTheDocument();
    expect(within(region).getByText("Established by the application, not the model")).toBeInTheDocument();
    expect(within(region).getByText("The container is running and readiness is false.")).toBeInTheDocument();
    expect(within(region).getByText("Model-generated. Ranked by evidence fit, not probability.")).toBeInTheDocument();
    expect(within(finding).queryByText(/readiness probe may be failing/)).not.toBeInTheDocument();
    // No invented confidence of any kind.
    expect(document.body.textContent).not.toMatch(/confidence|\d+\s?%/i);
  });

  it("summarises its evidence as a count and states each reference's role when opened", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    const region = topHypothesis();
    expect(within(region).queryByText("ev-0042")).not.toBeInTheDocument();

    await expandEvidence(user, region);
    expect(within(region).getByRole("button", { name: "Supporting evidence · 3 references" })).toHaveAttribute("aria-expanded", "true");

    const items = [...within(region).getByRole("list", { name: "Evidence for hypothesis 1" }).children] as HTMLElement[];
    expect(items.map((item) => within(item).getAllByRole("button")[0]!.textContent)).toEqual(["ev-0005", "ev-0042", "ev-0007"]);
    expect(within(items[0]!).getByText(/cited by the AI/)).toBeInTheDocument();
    expect(within(items[2]!).getByText(/supports the application's statement/)).toBeInTheDocument();
    expect(within(items[1]!).getByText(/Details unavailable/)).toBeInTheDocument();
  });

  it("keeps declared-configuration context out of the hypothesis card and under Findings", async () => {
    const base = report();
    completed({
      ...base,
      ai_hypotheses: [
        { ...base.ai_hypotheses[0]!, configuration_context: "Container 'app' declares no environment variables.", configuration_refs: ["ev-0009"] },
      ],
    });
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    expect(within(topHypothesis()).queryByText(/declares no environment variables/)).not.toBeInTheDocument();

    await user.click(within(panel()).getByRole("button", { name: /Configuration observations/ }));
    expect(within(panel()).getByText(/declares no environment variables/)).toBeInTheDocument();
    expect(within(panel()).getByText(/referenced by unverified hypothesis #1/)).toBeInTheDocument();
    // Its references are still reachable.
    expect(screen.getByRole("tab", { name: "Findings 3" })).toBeInTheDocument();
  });

  it("lists a configuration statement shared by several hypotheses once", async () => {
    const base = report();
    const shared = { ...base.ai_hypotheses[0]!, configuration_context: "Container 'app' declares no environment variables.", configuration_refs: ["ev-0009"] };
    completed({ ...base, ai_hypotheses: [shared, { ...shared, possible_explanation: "Second." }, { ...shared, possible_explanation: "Third." }] });
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    expect(screen.getByRole("tab", { name: "Findings 3" })).toBeInTheDocument();
    await user.click(within(panel()).getByRole("button", { name: /Configuration observations/ }));

    expect(within(panel()).getAllByText(/declares no environment variables/)).toHaveLength(1);
    expect(within(panel()).getByText(/referenced by unverified hypotheses #1, #2, #3/)).toBeInTheDocument();
  });

  it("collapses the remaining hypotheses in ranking order, each still unverified with its own check", async () => {
    const base = report();
    const second = { ...base.ai_hypotheses[0]!, possible_explanation: "The probe port may be wrong.", verification_check: "Compare the probe port with the container port.", evidence_refs: ["ev-0009"], established_refs: [] , independently_established: null };
    const third = { ...second, possible_explanation: "The probe timeout may be too short.", verification_check: "Read the declared probe timeout.", evidence_refs: ["ev-0003"] };
    completed({ ...base, ai_hypotheses: [base.ai_hypotheses[0]!, second, third] });
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    const region = screen.getByRole("region", { name: "Other AI hypotheses" });

    expect(within(region).queryByText(/The probe port may be wrong/)).not.toBeInTheDocument();
    await user.click(within(region).getByRole("button", { name: /Other hypotheses/ }));

    const rows = within(region).getAllByRole("button", { name: /^#\d/ });
    expect(rows.map((row) => row.textContent)).toEqual(["#2The probe port may be wrong.", "#3The probe timeout may be too short."]);
    expect(within(region).getAllByText("UNVERIFIED")).toHaveLength(1);

    await user.click(rows[0]!);
    expect(within(region).getByText("Compare the probe port with the container port.")).toBeInTheDocument();
    expect(within(region).getByRole("button", { name: "Supporting evidence · 1 reference" })).toBeInTheDocument();
    // The top hypothesis is not duplicated here.
    expect(within(region).queryByText(/readiness probe may be failing/)).not.toBeInTheDocument();
  });

  it("says a check was withheld, and why, instead of showing a check the application rejected", async () => {
    const base = report();
    const second = {
      ...base.ai_hypotheses[0]!,
      possible_explanation: "The probe port may be wrong.",
      verification_check: null,
      check_withheld_reason: "remediation_in_check",
      evidence_refs: ["ev-0009"],
      established_refs: [],
      independently_established: null,
    };
    completed({ ...base, ai_hypotheses: [base.ai_hypotheses[0]!, second] });
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    const region = screen.getByRole("region", { name: "Other AI hypotheses" });
    await user.click(within(region).getByRole("button", { name: /Other hypotheses/ }));
    await user.click(within(region).getAllByRole("button", { name: /^#\d/ })[0]!);

    expect(within(region).getByText(/Withheld: Recommended an action instead of a read-only check/)).toBeInTheDocument();
    expect(within(region).queryByText(/Suggested read-only check \(not performed\)/)).not.toBeInTheDocument();
  });

  it("says that no hypotheses passed validation and discloses why under Limitations", async () => {
    completed(
      report({
        ai_hypotheses: [],
        ai_analysis: {
          state: "all_omitted", reason: null, message: "All 3 proposed hypotheses were omitted by validation. See omission_reasons.",
          log_excerpts_used: 0, log_excerpts_omitted: 0, hypotheses_omitted: 3, hypotheses_proposed: 3,
          omission_reasons: { contradicts_container_state: 2, misattributed_source: 1 }, rejection_category: null,
        },
      }),
    );
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    const region = topHypothesis();

    expect(within(region).getByText(NO_HYPOTHESES_MESSAGE)).toBeInTheDocument();
    expect(within(region).queryByText("UNVERIFIED")).not.toBeInTheDocument();
    expect(within(region).queryByText(/omission_reasons/)).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Other AI hypotheses" })).not.toBeInTheDocument();

    await openTab(user, "Limitations");
    expect(screen.getByText(/3 of 3 proposed AI hypotheses were omitted/)).toBeInTheDocument();
    expect(screen.getByText(/Contradicted the container's observed state \(×2\)/)).toBeInTheDocument();
    expect(screen.getByText(/Presented a Kubernetes state as an application log/)).toBeInTheDocument();
  });
});

describe("next diagnostic step", () => {
  it("shows the hypothesis's check once, labelled as a read-only check that was not performed", async () => {
    completed();
    renderApp(route, api);
    await primary();

    const check = nextCheckRegion();

    expect(within(check).getByText("Inspect the declared probe through read-only describe output.")).toBeInTheDocument();
    expect(within(check).getByText("Read-only check · not performed")).toBeInTheDocument();
    // The disclaimer is not repeated here: the badge already says it was not run.
    expect(within(check).queryByText(/never changes the cluster|does not run it/)).not.toBeInTheDocument();
    expect(within(topHypothesis()).queryByText(/Inspect the declared probe/)).not.toBeInTheDocument();
    expect(screen.getAllByText(/Inspect the declared probe/)).toHaveLength(1);
  });

  it("labels a report-level suggestion as guidance for review, not as a read-only check", async () => {
    completed(report({ ai_hypotheses: [], suggested_checks: ["Ask the workload owner to review the entrypoint."] }));
    renderApp(route, api);
    await primary();

    const check = nextCheckRegion();

    expect(within(check).getByText("Ask the workload owner to review the entrypoint.")).toBeInTheDocument();
    expect(within(check).getByText("Suggested check · for review · not performed")).toBeInTheDocument();
    expect(within(check).queryByText(/Read-only check/)).not.toBeInTheDocument();
    expect(within(check).getByText("Guidance for a person to review. This console does not run it.")).toBeInTheDocument();
    expect(within(check).queryByText(/Written for hypothesis/)).not.toBeInTheDocument();
    expect(within(check).queryByRole("button")).not.toBeInTheDocument();
  });

  it("keeps every other suggested check under Findings and never repeats the recommended one", async () => {
    completed(
      report({
        suggested_checks: [
          "Inspect the declared probe through read-only describe output.",
          "Review the readiness probe path through read-only describe output.",
        ],
      }),
    );
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    await user.click(within(panel()).getByRole("button", { name: /Other suggested checks/ }));

    expect(within(panel()).getByText("Review the readiness probe path through read-only describe output.")).toBeInTheDocument();
    expect(screen.getAllByText(/Inspect the declared probe/)).toHaveLength(1);
  });

  it("says plainly when there is no suggested check", async () => {
    completed(report({ ai_hypotheses: [], suggested_checks: [] }));
    renderApp(route, api);
    await primary();

    expect(within(nextCheckRegion()).getByText("The report contains no suggested checks.")).toBeInTheDocument();
  });
});

describe("technical details: findings", () => {
  it("lists the remaining observations once, collapsed, and nothing is lost on expansion", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    expect(screen.getByRole("tab", { name: "Findings 2" })).toHaveAttribute("aria-selected", "true");
    expect(within(panel()).queryByText("Kubernetes reported pod phase 'Running'.")).not.toBeInTheDocument();

    await user.click(within(panel()).getByRole("button", { name: /Observed state/ }));
    expect(within(panel()).getByText("Pod phase observed")).toBeInTheDocument();
    expect(within(panel()).getByText("Kubernetes reported pod phase 'Running'.")).toBeInTheDocument();

    await user.click(within(panel()).getByRole("button", { name: /Configuration observations/ }));
    expect(within(panel()).getByText("Container 'app': image 'nginx:1.27'.")).toBeInTheDocument();
  });

  it("folds observations already cited by a finding into one group instead of repeating them", async () => {
    completed(
      report({
        findings: [
          { title: "Container is crash-looping", description: "Back-off restarting.", severity: "critical", evidence: [{ evidence_id: "ev-0001" }, { evidence_id: "ev-0002" }] },
          { title: "Container restart count observed", description: "Restarted 37 times.", severity: "info", evidence: [{ evidence_id: "ev-0001" }] },
          { title: "Pod phase observed", description: "Phase Running.", severity: "info", evidence: [{ evidence_id: "ev-0002" }] },
          { title: "Container configuration observed", description: "Image nginx.", severity: "info", evidence: [{ evidence_id: "ev-0009" }] },
        ],
        ai_hypotheses: [],
      }),
    );
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    expect(screen.queryByText("Restarted 37 times.")).not.toBeInTheDocument();
    await user.click(within(panel()).getByRole("button", { name: /Underlying observations/ }));
    expect(within(panel()).getByText("Container restart count observed")).toBeInTheDocument();
    expect(within(panel()).getByText("Restarted 37 times.")).toBeInTheDocument();
    expect(within(panel()).getByText("Pod phase observed")).toBeInTheDocument();
    // An observation no finding cites stays in its own group.
    expect(within(panel()).queryByText("Container configuration observed")).not.toBeInTheDocument();
    await user.click(within(panel()).getByRole("button", { name: /Configuration observations/ }));
    expect(within(panel()).getByText("Container configuration observed")).toBeInTheDocument();
  });

  it("says when the primary finding is the only one", async () => {
    completed(report({ findings: [report().findings[0]!], ai_hypotheses: [] }));
    renderApp(route, api);
    await primary();

    expect(screen.getByRole("tab", { name: "Findings 0" })).toBeInTheDocument();
    expect(within(panel()).getByText(/primary finding above is the only one recorded/)).toBeInTheDocument();
  });
});

describe("technical details: tabs", () => {
  it("offers Findings, Evidence, Audit and Limitations with counts, Findings first", async () => {
    completed();
    renderApp(route, api);
    await primary();

    const tabs = within(screen.getByRole("tablist", { name: "Technical details" })).getAllByRole("tab");

    expect(tabs.map((tab) => tab.textContent?.replace(/\s*\d+$/, ""))).toEqual(["Findings", "Evidence", "Audit", "Limitations"]);
    expect(tabs[0]).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: "Evidence 5" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole("tab", { name: "Audit 4" })).toBeInTheDocument());
    expect(screen.getByRole("tab", { name: /Limitations \d+/ })).toBeInTheDocument();
  });

  it("supports keyboard navigation between tabs", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    screen.getByRole("tab", { name: /^Findings/ }).focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: /^Evidence/ })).toHaveAttribute("aria-selected", "true");
    expect(screen.getByRole("tab", { name: /^Evidence/ })).toHaveFocus();
    expect(screen.getByRole("tabpanel")).toHaveAccessibleName(/^Evidence/);

    await user.keyboard("{End}");
    expect(screen.getByRole("tab", { name: /^Limitations/ })).toHaveAttribute("aria-selected", "true");

    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: /^Findings/ })).toHaveAttribute("aria-selected", "true");
  });
});

describe("evidence navigation", () => {
  it("lists every reference once in the Evidence tab", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();
    await openTab(user, "Evidence");

    const list = screen.getByRole("list", { name: "Evidence references" });

    for (const id of ["ev-0003", "ev-0005", "ev-0007", "ev-0009", "ev-0042"]) {
      expect(list.querySelector(`#evidence-${id}`)).not.toBeNull();
    }
    expect(within(list).getAllByRole("listitem")).toHaveLength(5);
  });

  it("opens a reference from a finding: switches to Evidence, expands the row and says what the report can say", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);

    const region = await primary();
    expect(screen.queryByRole("list", { name: "Evidence references" })).not.toBeInTheDocument();

    await expandEvidence(user, region);
    await user.click(within(region).getByRole("button", { name: "Open evidence ev-0005" }));

    expect(screen.getByRole("tab", { name: /^Evidence/ })).toHaveAttribute("aria-selected", "true");
    const row = document.getElementById("evidence-ev-0005") as HTMLElement;

    expect(within(row).getByRole("button", { expanded: true })).toBeInTheDocument();
    expect(within(row).getByText("Verified observation")).toBeInTheDocument();
    expect(within(row).getByText("Container is running but not ready")).toBeInTheDocument();
    expect(within(row).getByText(/Container 'app' is running but Kubernetes reports it is not ready/)).toBeInTheDocument();
    expect(within(row).getByText(/Cited by unverified AI hypothesis #1/)).toBeInTheDocument();
    expect(screen.getByText(/returns reference ids, not raw observations/)).toBeInTheDocument();
  });

  it("shows 'details unavailable' for a citation no finding can resolve, and never invents content", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    const region = topHypothesis();
    await expandEvidence(user, region);
    await user.click(within(region).getByRole("button", { name: "Open evidence ev-0042" }));

    const row = document.getElementById("evidence-ev-0042") as HTMLElement;

    expect(within(row).getByText(/Details unavailable/)).toBeInTheDocument();
    expect(row.textContent).not.toMatch(/readiness=false|state=running/);
  });

  it("treats a log reference as untrusted and does not show its text", async () => {
    const r = report();
    r.ai_hypotheses[0] = { ...r.ai_hypotheses[0]!, reported: "the probe path was not found", evidence_refs: ["ev-0005", "log-0001"] };
    completed(r);
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    const region = topHypothesis();
    expect(within(region).getByText(/an unverified claim from untrusted log text/)).toBeInTheDocument();
    await expandEvidence(user, region);
    await user.click(within(region).getByRole("button", { name: "Open evidence log-0001" }));

    const row = document.getElementById("evidence-log-0001") as HTMLElement;

    expect(within(row).getByText("Untrusted log")).toBeInTheDocument();
    expect(within(row).getByText(/Untrusted application log excerpt/)).toBeInTheDocument();
  });

  it("shows an empty-evidence message when the report cites nothing", async () => {
    completed(report({ findings: [{ title: "Pod phase observed", description: "x", severity: "info", evidence: [] }], ai_hypotheses: [] }));
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();
    await openTab(user, "Evidence");

    expect(screen.getByText("This report cites no evidence references.")).toBeInTheDocument();
  });
});

describe("audit history", () => {
  it("shows backend events in order with fixed rejection codes, never synthesized ones", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();
    await openTab(user, "Audit");

    const events = within(await screen.findByRole("list", { name: "Audit events" })).getAllByRole("listitem");

    expect(events).toHaveLength(4);
    expect(within(events[0]!).getByText("Proposed")).toBeInTheDocument();
    expect(within(events[1]!).getByText("Authorized")).toBeInTheDocument();
    expect(within(events[3]!).getByText("Rejected")).toBeInTheDocument();
    expect(within(events[3]!).getByText("outside_target")).toBeInTheDocument();
    expect(within(events[3]!).getByText(/inspect something other than the bound workload/)).toBeInTheDocument();
    expect(within(events[3]!).getByText(/pod=other-pod/)).toBeInTheDocument();
    expect(screen.getByText(/4 events · 1 rejected/)).toBeInTheDocument();
    expect(events[0]!.querySelector("time")).toHaveAttribute("title");
  });

  it("shows an unknown reason code as the raw code only", async () => {
    api.on(`GET /api/investigations/${ID}/summary`, { body: summary() });
    api.on(`GET /api/investigations/${ID}/report`, { body: report() });
    const trail = audit();
    trail.events[3] = { ...trail.events[3]!, reason_code: "some_new_code" };
    api.on(`GET /api/investigations/${ID}/audit`, { body: trail });
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();
    await openTab(user, "Audit");

    expect(await screen.findByText("some_new_code")).toBeInTheDocument();
  });

  it("handles an empty record and a failed audit load without hiding the report", async () => {
    api.on(`GET /api/investigations/${ID}/summary`, { body: summary() });
    api.on(`GET /api/investigations/${ID}/report`, { body: report() });
    api.on(`GET /api/investigations/${ID}/audit`, { body: audit({ events: [] }) });
    const user = userEvent.setup();
    const first = renderApp(route, api);
    await primary();
    await openTab(user, "Audit");

    expect(await screen.findByText("No audit events are recorded for this investigation.")).toBeInTheDocument();
    first.unmount();

    api.on(`GET /api/investigations/${ID}/audit`, { status: 404, body: {} });
    renderApp(route, api);
    await primary();
    await openTab(user, "Audit");

    expect(await screen.findByText("Could not load the audit trail")).toBeInTheDocument();
    expect(screen.getByRole("region", { name: "Primary verified finding" })).toBeInTheDocument();
  });

  it("flags a truncated record", async () => {
    api.on(`GET /api/investigations/${ID}/summary`, { body: summary() });
    api.on(`GET /api/investigations/${ID}/report`, { body: report() });
    api.on(`GET /api/investigations/${ID}/audit`, { body: audit({ truncated: true }) });
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();
    await openTab(user, "Audit");

    expect(await screen.findByText(/longer than this view/)).toBeInTheDocument();
  });
});

describe("coverage limitations", () => {
  it("discloses uncertainties, rejected proposals, omitted hypotheses and the absence of logs, and states the caveat once", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();
    await waitFor(() => expect(screen.getByRole("tab", { name: "Audit 4" })).toBeInTheDocument());
    await openTab(user, "Limitations");

    const list = screen.getByRole("list", { name: "Limitations and uncertainties" });

    expect(within(list).getByText(/Container logs were not retrieved/)).toBeInTheDocument();
    expect(within(list).getByText(/2 of 3 proposed AI hypotheses were omitted by validation/)).toBeInTheDocument();
    expect(within(list).getByText(/No log excerpts were used/)).toBeInTheDocument();
    expect(within(list).getByText(/1 model-proposed tool call was rejected/)).toBeInTheDocument();
    expect(within(list).getByText(/provider_finished/)).toBeInTheDocument();
    expect(within(list).getAllByText(/do not establish a root cause/)).toHaveLength(1);
  });

  it("flags the Limitations tab with its count so caveats are visible without opening it", async () => {
    completed();
    renderApp(route, api);
    await primary();

    const tab = screen.getByRole("tab", { name: /^Limitations/ });

    expect(within(tab).getByText(/^\d+$/)).toHaveClass("text-warning");
  });

  it("discloses partial pod coverage and that AI analysis was unavailable", async () => {
    completed(
      report({
        uncertainties: ["Only 1 of 2 pods was inspected; the second pod's state is unknown."],
        ai_hypotheses: [],
        ai_analysis: { state: "unavailable", reason: "timeout", message: "AI analysis unavailable.", log_excerpts_used: 0, log_excerpts_omitted: 0, hypotheses_omitted: 0, hypotheses_proposed: 0, omission_reasons: {}, rejection_category: null },
      }),
    );
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();
    await openTab(user, "Limitations");

    expect(screen.getByText(/Only 1 of 2 pods was inspected/)).toBeInTheDocument();
    expect(screen.getByText(/AI analysis was unavailable \(The AI stage timed out\.\)/)).toBeInTheDocument();
  });
});

describe("other states", () => {
  it("renders a failed investigation without inventing a report", async () => {
    api.on(`GET /api/investigations/${ID}/summary`, {
      body: summary({ status: "failed", stop_reason: "tool_failed", primary_finding: null, finding_counts: null }),
    });
    api.on(`GET /api/investigations/${ID}/audit`, { body: audit() });
    renderApp(route, api);

    expect(await screen.findByText("Investigation failed")).toBeInTheDocument();
    expect(screen.getByText(/read-only Kubernetes call failed/)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Primary verified finding" })).not.toBeInTheDocument();
    expect(api.count(`GET /api/investigations/${ID}/report`)).toBe(0);
    expect(await screen.findByRole("list", { name: "Audit events" })).toBeInTheDocument();
  });

  it("shows not-found without leaking whether the id exists elsewhere", async () => {
    api.on(`GET /api/investigations/${ID}/summary`, { status: 404, body: { detail: "Investigation not found." } });
    renderApp(route, api);

    expect(await screen.findByText("Investigation not found")).toBeInTheDocument();
    expect(screen.getByText(/may not exist/)).toBeInTheDocument();
  });

  it("offers an explicit start for a pending investigation and starts it exactly once", async () => {
    api.on(`GET /api/investigations/${ID}/summary`, { body: summary({ status: "pending", started_at: null, finished_at: null, duration_seconds: null, primary_finding: null, finding_counts: null }) });
    api.on(`GET /api/investigations/${ID}/audit`, { body: audit({ events: [] }) });
    api.on(`POST /api/investigations/${ID}/execute`, { body: {} });
    const user = userEvent.setup();
    renderApp(route, api);

    const start = await screen.findByRole("button", { name: "Start investigation" });
    expect(api.count(`POST /api/investigations/${ID}/execute`)).toBe(0);

    await user.click(start);
    await waitFor(() => expect(api.count(`POST /api/investigations/${ID}/execute`)).toBe(1));
    expect(screen.queryByRole("button", { name: "Start investigation" })).not.toBeInTheDocument();
  });

  it("polls a running investigation on a bounded interval and loads the report when it completes", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let status: "running" | "completed" = "running";
    api.on(`GET /api/investigations/${ID}/summary`, () => ({ body: status === "running" ? summary({ status: "running", finished_at: null, duration_seconds: null, primary_finding: null, finding_counts: null }) : summary() }));
    api.on(`GET /api/investigations/${ID}/report`, { body: report() });
    api.on(`GET /api/investigations/${ID}/audit`, { body: audit() });
    renderApp(route, api);

    expect(await screen.findByText(/This page refreshes every 2 seconds/)).toBeInTheDocument();
    expect(api.count(`GET /api/investigations/${ID}/report`)).toBe(0);

    status = "completed";
    await act(async () => {
      await vi.advanceTimersByTimeAsync(2100);
    });

    expect(await screen.findByRole("region", { name: "Primary verified finding" })).toBeInTheDocument();
    const polls = api.count(`GET /api/investigations/${ID}/summary`);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });

    // Terminal status: polling stops.
    expect(api.count(`GET /api/investigations/${ID}/summary`)).toBe(polls);
  });

});

describe("read-only boundary and safe rendering", () => {
  it("has no execute, apply, restart, delete or remediation controls in a completed report", async () => {
    completed();
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    const check = (label: string) => expect(label).not.toMatch(/\b(execute|apply|restart|delete|remediat|fix|scale|rollback|exec|kubectl)\b/i);

    for (const name of ["Findings", "Evidence", "Audit", "Limitations"]) {
      await openTab(user, name);
      for (const button of screen.getAllByRole("button")) check(button.textContent ?? "");
    }
    // The check is distinguished by its label, not by repeated disclaimers.
    expect(within(nextCheckRegion()).getByText("Read-only check · not performed")).toBeInTheDocument();
  });

  it("renders malicious report text as inert text", async () => {
    const evil = `<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>`;
    const r = report({
      summary: evil,
      uncertainties: [evil],
      suggested_checks: [evil, evil + "2"],
      findings: [{ title: evil, description: `${evil} javascript:alert(1)`, severity: "critical", evidence: [{ evidence_id: "ev-0001" }] }],
      ai_hypotheses: [{ ...report().ai_hypotheses[0]!, possible_explanation: evil, not_yet_verified: evil, verification_check: evil, reported: evil, independently_established: evil }],
    });
    completed(r);
    const user = userEvent.setup();
    renderApp(route, api);

    await primary();

    expect(screen.getAllByText(/<img src=x/).length).toBeGreaterThanOrEqual(5);
    await openTab(user, "Limitations");
    expect(screen.getAllByText(/<img src=x/).length).toBeGreaterThanOrEqual(7);

    expect(document.querySelector("img")).toBeNull();
    expect(document.querySelector("script")).toBeNull();
    expect((window as unknown as { __pwned?: number }).__pwned).toBeUndefined();
    expect(document.querySelector("a[href^='javascript:']")).toBeNull();
  });
});

describe("namespace-wide resource groups", () => {
  const hogCheck = "Review the memory configuration of container app in pod hog-pod.";
  const baseHypothesis = report().ai_hypotheses[0]!;

  function namespaceReport(): InvestigationReport {
    const diagnostic: NamespaceDiagnostic = {
      listed_pods: 5,
      inspected_pods: 4,
      uninspected_pods: 1,
      unsuccessful_pods: 0,
      listing_truncated: false,
      assessment_complete: false,
      resources: [
        {
          namespace: "ai-ops-demo",
          kind: "Deployment",
          name: "ceb",
          ownership: "verified",
          pods: ["ceb-pod"],
          findings: [{ index: 0, pod: "ceb-pod" }],
          hypothesis_indexes: [],
          checks: [],
        },
        {
          namespace: "ai-ops-demo",
          kind: "Deployment",
          name: "hog",
          ownership: "verified",
          pods: ["hog-pod"],
          findings: [{ index: 1, pod: "hog-pod" }],
          hypothesis_indexes: [0],
          coverage: "established",
          deeply_investigated: false,
          checks: [
            {
              text: hogCheck,
              source: "hypothesis",
              hypothesis_index: 0,
              pod: "hog-pod",
              container: "app",
            },
          ],
        },
        {
          namespace: "ai-ops-demo",
          kind: "Deployment",
          name: "quiet",
          ownership: "verified",
          pods: ["quiet-pod"],
          findings: [{ index: 2, pod: "quiet-pod" }],
          hypothesis_indexes: [],
          checks: [],
        },
        {
          namespace: "ai-ops-demo",
          kind: "Pod",
          name: "orphan-pod",
          ownership: "unresolved",
          pods: ["orphan-pod"],
          findings: [{ index: 3, pod: "orphan-pod" }],
          hypothesis_indexes: [],
          checks: [],
        },
        {
          namespace: "ai-ops-demo",
          kind: "Pod",
          name: "missed-pod",
          ownership: "verified",
          pods: ["missed-pod"],
          findings: [],
          hypothesis_indexes: [],
          checks: [],
          coverage: "unknown",
        },
      ],
      shared_findings: [{ index: 4, pod: null }],
      shared_hypothesis_indexes: [],
      shared_checks: [],
    };

    return report({
      findings: [
        {
          title: "Image pull is backing off",
          description: "ImagePullBackOff. The prose mentions hog but the evidence is ceb.",
          severity: "critical",
          evidence: [{ evidence_id: "ev-0005" }],
        },
        {
          title: "Container was OOMKilled",
          description: "The previous termination reason was OOMKilled.",
          severity: "critical",
          evidence: [{ evidence_id: "ev-0007" }],
        },
        {
          title: "Container restarted earlier and is running now",
          description: "The container is ready and has restarted before.",
          severity: "warning",
          evidence: [{ evidence_id: "ev-0003" }],
        },
        {
          title: "Container is crash-looping",
          description: "The pod is waiting.",
          severity: "warning",
          evidence: [{ evidence_id: "ev-0009" }],
        },
        {
          title: "Events were read",
          description: "These events are not attributed to one workload.",
          severity: "warning",
          evidence: [{ evidence_id: "ev-0001" }],
        },
      ],
      ai_hypotheses: [
        {
          ...baseHypothesis,
          possible_explanation: "Memory pressure may explain the earlier termination.",
          verification_check: hogCheck,
          resource: { namespace: "ai-ops-demo", pod: "hog-pod", container: "app" },
        },
      ],
      suggested_checks: [hogCheck],
      namespace_diagnostic: diagnostic,
    });
  }

  function openNamespace() {
    api.on(`GET /api/investigations/${ID}/summary`, {
      body: summary({ scope: { mode: "namespace", kind: null, name: null } }),
    });
    api.on(`GET /api/investigations/${ID}/report`, { body: namespaceReport() });
    api.on(`GET /api/investigations/${ID}/audit`, { body: audit() });
    renderApp(route, api);
  }

  it("does not present one workload's hypothesis as another's finding", async () => {
    openNamespace();
    const user = userEvent.setup();

    const summary = await screen.findByRole("region", { name: "Namespace summary" });
    expect(summary).toHaveTextContent("4 inspected of 5 listed");
    expect(summary).toHaveTextContent("Health assessment is incomplete");
    expect(summary).toHaveTextContent("unknown, not healthy");
    expect(screen.queryByRole("region", { name: "Primary verified finding" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Top AI hypothesis" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Recommended next check" })).not.toBeInTheDocument();

    const ceb = screen.getByRole("region", { name: "Deployment ceb" });
    expect(within(ceb).getByText("No accepted hypothesis")).toBeInTheDocument();
    await user.click(within(ceb).getByRole("button"));
    expect(within(ceb).getAllByText("Image pull is backing off").length).toBeGreaterThan(0);
    expect(within(ceb).getByText("No accepted AI hypothesis for this resource.")).toBeInTheDocument();
    expect(within(ceb).queryByText(hogCheck)).not.toBeInTheDocument();
    expect(within(ceb).queryByText(/Memory pressure/)).not.toBeInTheDocument();

    const hog = screen.getByRole("region", { name: "Deployment hog" });
    await user.click(within(hog).getByRole("button"));
    expect(within(hog).getAllByText("Container was OOMKilled").length).toBeGreaterThan(0);
    expect(within(hog).getByText(/Memory pressure/)).toBeInTheDocument();
    expect(within(hog).getByText(hogCheck)).toBeInTheDocument();
    expect(within(hog).getByText(/not deeply investigated/)).toBeInTheDocument();

    const missed = screen.getByRole("region", { name: "Pod missed-pod" });
    expect(within(missed).getByText("Health unknown")).toBeInTheDocument();
    await user.click(within(missed).getByRole("button"));
    expect(within(missed).getByText(/not health-inspected/)).toBeInTheDocument();
    expect(within(missed).queryByText("No abnormal condition was verified for this resource.")).not.toBeInTheDocument();

    const quiet = screen.getByRole("region", { name: "Deployment quiet" });
    expect(within(quiet).getByText("No accepted hypothesis")).toBeInTheDocument();
    await user.click(within(quiet).getByRole("button"));
    expect(within(quiet).getAllByText("Container restarted earlier and is running now").length).toBeGreaterThan(0);

    const orphan = screen.getByRole("region", { name: "Pod orphan-pod" });
    await user.click(within(orphan).getByRole("button"));
    expect(within(orphan).getByText(/controlling workload was not verified/)).toBeInTheDocument();
    expect(within(orphan).queryByText("Deployment")).not.toBeInTheDocument();

    expect(screen.getByRole("region", { name: "Namespace-level evidence" })).toHaveTextContent("Events were read");
    expect(screen.getByRole("tab", { name: /^Audit/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /^Limitations/ })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /^Findings/ })).toBeInTheDocument();
  });

  it("keeps a stored namespace report without groups out of the single-workload sequence", async () => {
    api.on(`GET /api/investigations/${ID}/summary`, {
      body: summary({ scope: { mode: "namespace", kind: null, name: null } }),
    });
    api.on(`GET /api/investigations/${ID}/report`, { body: report() });
    api.on(`GET /api/investigations/${ID}/audit`, { body: audit() });
    renderApp(route, api);

    expect(await screen.findByText(/stored without resource groups/)).toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Primary verified finding" })).not.toBeInTheDocument();
    expect(screen.queryByRole("region", { name: "Recommended next check" })).not.toBeInTheDocument();
    expect(screen.getByRole("region", { name: "AI hypothesis 1" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: /^Audit/ })).toBeInTheDocument();
  });
});
