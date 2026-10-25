import { screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ID, audit, report, summary } from "@/test/fixtures";
import { installMockApi, renderApp, resetApp, type MockApi } from "@/test/mockApi";
import type { Finding, InvestigationReport } from "@/types/api";

// An unschedulable pod. The description is the backend's own prose; the rows are
// the backend's validated, structured constraints. The browser reads only rows.
const DESCRIPTION =
  "Pod 'impossible-pod' is 'Pending' and Kubernetes marks its PodScheduled condition False with reason 'Unschedulable': Kubernetes reports that the scheduler could not place the pod on any node, so no container has been created. The scheduler's status message reports (classified by fixed patterns; the message itself is untrusted and not retained): insufficient CPU; insufficient memory; node taints the pod does not tolerate. Kubernetes recorded Warning event 'FailedScheduling' (x3) for this pod. This establishes that Kubernetes could not place the pod. It does not establish why the cluster cannot meet that constraint. Resource: namespace 'ai-ops-demo', pod 'impossible-pod'.";

const SCHEDULING: Finding = {
  title: "Pod could not be scheduled",
  description: DESCRIPTION,
  severity: "critical",
  evidence: ["ev-0003", "ev-0004", "ev-0010", "ev-0011", "ev-0012", "ev-0013", "ev-0014"].map((evidence_id) => ({ evidence_id })),
  scheduling_constraints: [
    { signal: "insufficient_cpu", label: "Insufficient CPU", evidence_ids: ["ev-0010", "ev-0013"] },
    { signal: "insufficient_memory", label: "Insufficient memory", evidence_ids: ["ev-0011", "ev-0014"] },
    { signal: "untolerated_taint", label: "Untolerated node taints", evidence_ids: ["ev-0012", "ev-0015", "ev-0016"] },
  ],
};

function scheduling(overrides: Partial<InvestigationReport> = {}): InvestigationReport {
  const base = report();

  return report({
    summary:
      "Investigation of namespace 'ai-ops-demo': 1 verified finding(s) (1 critical) from 18 trusted evidence item(s).\nTarget: Pod 'impossible-pod', verified by name.",
    findings: [SCHEDULING],
    ai_hypotheses: [
      {
        ...base.ai_hypotheses[0]!,
        possible_explanation: "The requested CPU and memory may exceed what any node can allocate.",
        verification_check: "Compare the pod's CPU and memory requests with the allocatable capacity of the nodes (read-only).",
        evidence_refs: ["ev-0010", "ev-0011"],
        established_refs: [],
        independently_established: null,
        resource: { namespace: "ai-ops-demo", pod: "impossible-pod", container: null },
      },
      {
        ...base.ai_hypotheses[0]!,
        possible_explanation: "The nodes may carry taints that the pod does not tolerate.",
        verification_check: "Compare the taints on the nodes with the tolerations the pod declares (read-only).",
        evidence_refs: ["ev-0012"],
        established_refs: [],
        independently_established: null,
        resource: { namespace: "ai-ops-demo", pod: "impossible-pod", container: null },
      },
    ],
    uncertainties: [],
    suggested_checks: [],
    ...overrides,
  });
}

let api: MockApi;
const route = `/investigations/${ID}`;
const primary = () => screen.findByRole("region", { name: "Primary verified finding" });
const rowsOf = (region: HTMLElement) => within(region).getByRole("list", { name: "Scheduling constraints reported by Kubernetes" });

function completed(r: InvestigationReport) {
  api.on(`GET /api/investigations/${ID}/summary`, { body: summary({ scope: { mode: "workload", kind: "Pod", name: "impossible-pod" } }) });
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

describe("scheduling constraints", () => {
  it("shows a concise primary finding with the constraints as compact rows", async () => {
    completed(scheduling());
    renderApp(route, api);

    const region = await primary();

    expect(within(region).getByRole("heading", { level: 2, name: "Pod could not be scheduled" })).toBeInTheDocument();
    expect(within(region).getByText("ai-ops-demo/impossible-pod")).toBeInTheDocument();

    const rows = [...rowsOf(region).children] as HTMLElement[];
    expect(rows.map((row) => within(row).getByText(/^(Insufficient|Untolerated)/).textContent)).toEqual([
      "Insufficient CPU",
      "Insufficient memory",
      "Untolerated node taints",
    ]);
    // Rows carry no prose of their own and no raw id list: at most two ids each.
    expect(within(rows[2]!).getAllByRole("button")).toHaveLength(2);
    expect(within(rows[2]!).getByText("+1")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("ev-0010")).toBeInTheDocument();
  });

  it("clamps the finding to two lines when rows carry the constraints, and keeps the full finding one click away", async () => {
    completed(scheduling());
    const user = userEvent.setup();
    renderApp(route, api);

    const region = await primary();
    const body = within(region).getByText(/could not place the pod on any node/);

    expect(body).toHaveClass("line-clamp-2");

    await user.click(within(region).getByRole("button", { name: "Show full finding" }));

    expect(body).not.toHaveClass("line-clamp-2");
    expect(body).toHaveTextContent(/node taints the pod does not tolerate/);
    expect(body).toHaveTextContent(/It does not establish why the cluster cannot meet that constraint/);
  });

  it("keeps the evidence references accessible and does not repeat the finding's resource line", async () => {
    completed(scheduling());
    const user = userEvent.setup();
    renderApp(route, api);

    const region = await primary();

    await user.click(within(region).getByRole("button", { name: "Supporting evidence · 7 references" }));
    expect(within(region).getByRole("list", { name: "Evidence for the primary finding" }).children).toHaveLength(7);
    expect(within(region).queryByText(/Resource: namespace/)).not.toBeInTheDocument();
  });

  it("opens a row's evidence in the Evidence tab and names the recorded scheduler signal", async () => {
    completed(scheduling());
    const user = userEvent.setup();
    renderApp(route, api);

    const region = await primary();

    await user.click(within(rowsOf(region)).getByRole("button", { name: "Open evidence ev-0010 for Insufficient CPU" }));

    expect(screen.getByRole("tab", { name: /^Evidence/ })).toHaveAttribute("aria-selected", "true");

    const row = document.getElementById("evidence-ev-0010") as HTMLElement;

    expect(within(row).getByRole("button", { expanded: true })).toBeInTheDocument();
    expect(within(row).getByText("Recorded scheduler signal:")).toBeInTheDocument();
    expect(within(row).getByText("Insufficient CPU")).toBeInTheDocument();
  });

  it("builds rows only from the structured field, never from the description's text", async () => {
    const { scheduling_constraints: _rows, ...withoutRows } = SCHEDULING;

    void _rows;
    completed(scheduling({ findings: [withoutRows] }));
    renderApp(route, api);

    const region = await primary();

    // The prose still mentions CPU, memory and taints; no row is derived from it.
    expect(within(region).getByText(/insufficient CPU; insufficient memory/)).toBeInTheDocument();
    expect(within(region).queryByRole("list", { name: "Scheduling constraints reported by Kubernetes" })).not.toBeInTheDocument();
    expect(within(region).queryByText("Reported by the scheduler")).not.toBeInTheDocument();
    // Without rows the long finding keeps the standard three-line clamp.
    expect(within(region).getByText(/could not place the pod on any node/)).toHaveClass("line-clamp-3");
  });

  it("treats an empty constraint list like an absent one", async () => {
    completed(scheduling({ findings: [{ ...SCHEDULING, scheduling_constraints: [] }] }));
    renderApp(route, api);

    const region = await primary();

    expect(within(region).queryByText("Reported by the scheduler")).not.toBeInTheDocument();
  });

  it("renders a hostile label as inert text", async () => {
    const evil = `<img src=x onerror="window.__pwned=1">`;
    completed(
      scheduling({
        findings: [{ ...SCHEDULING, scheduling_constraints: [{ signal: "insufficient_cpu", label: evil, evidence_ids: ["ev-0010"] }] }],
      }),
    );
    renderApp(route, api);

    const region = await primary();

    expect(within(region).getByText(evil)).toBeInTheDocument();
    expect(region.querySelector("img")).toBeNull();
  });

  it("shows constraint rows for a further unschedulable pod under Findings", async () => {
    const second: Finding = {
      ...SCHEDULING,
      severity: "warning",
      title: "Second pod could not be scheduled",
      scheduling_constraints: [{ signal: "node_selector_mismatch", label: "Node selector or affinity mismatch", evidence_ids: ["ev-0010"] }],
    };
    completed(scheduling({ findings: [SCHEDULING, second] }));
    const user = userEvent.setup();
    renderApp(route, api);
    await primary();

    await user.click(within(screen.getByRole("tabpanel")).getByRole("button", { name: /Second pod could not be scheduled/ }));

    expect(within(screen.getByRole("tabpanel")).getByText("Node selector or affinity mismatch")).toBeInTheDocument();
  });

  it("keeps the AI analysis unverified and separate from the verified rows", async () => {
    completed(scheduling());
    renderApp(route, api);

    const finding = await primary();
    const ai = screen.getByRole("region", { name: "Top AI hypothesis" });

    expect(within(ai).getByText("UNVERIFIED")).toBeInTheDocument();
    expect(within(finding).queryByText("UNVERIFIED")).not.toBeInTheDocument();
    expect(within(ai).getByText(/CPU and memory may exceed what any node can allocate/)).toBeInTheDocument();
    expect(within(ai).queryByRole("list", { name: "Scheduling constraints reported by Kubernetes" })).not.toBeInTheDocument();
  });

  it("states taints on nodes and tolerations on pods in the recommended check, as the backend wrote it", async () => {
    const base = scheduling();
    completed({
      ...base,
      ai_hypotheses: [base.ai_hypotheses[1]!, base.ai_hypotheses[0]!],
    });
    renderApp(route, api);
    await primary();

    expect(
      within(screen.getByRole("region", { name: "Recommended next check" })).getByText(
        "Compare the taints on the nodes with the tolerations the pod declares (read-only).",
      ),
    ).toBeInTheDocument();
  });
});
