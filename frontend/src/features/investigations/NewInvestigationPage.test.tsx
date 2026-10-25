import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SCOPE_MESSAGES } from "@/api/scopeMessages";
import { ID, summary, audit } from "@/test/fixtures";
import { installMockApi, renderApp, resetApp, type MockApi } from "@/test/mockApi";
import { validate } from "./NewInvestigationPage";

let api: MockApi;
const record = {
  investigation_id: ID, authorized_namespace: "ai-ops-demo", status: "pending", created_at: "2026-10-18T10:00:00Z",
  started_at: null, finished_at: null, stop_reason: null, user_text: "q", max_steps: 6,
};

beforeEach(() => {
  api = installMockApi();
  api.on("GET /api/health", { body: { status: "ok", database: true } });
  // The detail page the form navigates to.
  api.on(`GET /api/investigations/${ID}/summary`, { body: summary({ status: "running", finished_at: null, duration_seconds: null, primary_finding: null, finding_counts: null }) });
  api.on(`GET /api/investigations/${ID}/audit`, { body: audit({ events: [] }) });
  api.on(`POST /api/investigations/${ID}/execute`, { body: { ...record, status: "completed" } });
});
afterEach(resetApp);

describe("form validation", () => {
  it("validates the namespace, workload name and question", () => {
    expect(validate({ namespace: "ns", scope: "workload", name: "bad-readiness", question: "why" })).toEqual({});
    expect(validate({ namespace: "", scope: "workload", name: "x", question: "q" }).namespace).toBeDefined();
    expect(validate({ namespace: "ns", scope: "workload", name: "", question: "q" }).name).toBeDefined();
    expect(validate({ namespace: "ns", scope: "workload", name: "Bad_Name", question: "q" }).name).toBeDefined();
    expect(validate({ namespace: "ns", scope: "workload", name: "-x", question: "q" }).name).toBeDefined();
    expect(validate({ namespace: "ns", scope: "workload", name: "a".repeat(64), question: "q" }).name).toBeDefined();
    expect(validate({ namespace: "ns", scope: "workload", name: "ok", question: "  " }).question).toBeDefined();
    // A namespace-wide scope needs no workload name.
    expect(validate({ namespace: "ns", scope: "namespace", name: "", question: "q" })).toEqual({});
  });
});

describe("New investigation", () => {
  it("lists the demo namespaces and defaults to one workload", async () => {
    renderApp("/investigations/new", api);

    expect(await screen.findByRole("option", { name: "ai-ops-demo" })).toBeInTheDocument();
    expect(screen.getByLabelText("One workload")).toBeChecked();
    expect(screen.getByLabelText("Workload name")).toBeInTheDocument();
  });

  it("clears a workload-name error after a valid name or a whole-namespace scope", async () => {
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.click(await screen.findByRole("button", { name: "Investigate" }));
    expect(await screen.findByText("Enter the exact workload name.")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Workload name"), "bad-readiness");
    expect(screen.queryByText("Enter the exact workload name.")).not.toBeInTheDocument();

    await user.clear(screen.getByLabelText("Workload name"));
    await user.click(screen.getByRole("button", { name: "Investigate" }));
    expect(screen.getByText("Enter the exact workload name.")).toBeInTheDocument();

    await user.click(screen.getByLabelText("Whole namespace (broad)"));
    expect(screen.queryByText("Enter the exact workload name.")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Workload name")).not.toBeInTheDocument();

    await user.click(screen.getByLabelText("One workload"));
    expect(screen.getByText("Enter the exact workload name.")).toBeInTheDocument();
  });

  it("blocks submission with clear errors and sends nothing", async () => {
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.click(await screen.findByRole("button", { name: "Investigate" }));

    expect(await screen.findByText("Enter the exact workload name.")).toBeInTheDocument();
    expect(api.count("POST /api/investigations")).toBe(0);
  });

  it("creates with an explicit target, then executes once and shows the detail page", async () => {
    api.on("POST /api/investigations", { status: 201, body: record });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.type(await screen.findByLabelText("Workload name"), "bad-readiness");
    await user.click(screen.getByRole("button", { name: "Investigate" }));

    await waitFor(() => expect(api.count(`POST /api/investigations/${ID}/execute`)).toBe(1));
    expect(api.calls.find((c) => c.path === "POST /api/investigations")?.body).toEqual({
      namespace: "ai-ops-demo",
      question: "Why is this workload unhealthy?",
      target: { kind: "Deployment", name: "bad-readiness" },
    });
    expect((await screen.findAllByText("Running")).length).toBeGreaterThan(0);
  });

  it("sends an explicit, labelled namespace-wide scope and never a target with it", async () => {
    api.on("POST /api/investigations", { status: 201, body: record });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.click(await screen.findByLabelText("Whole namespace (broad)"));

    expect(screen.queryByLabelText("Workload name")).not.toBeInTheDocument();
    expect(screen.getByText(/never used as a fallback/i)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Investigate" }));
    await waitFor(() => expect(api.count("POST /api/investigations")).toBe(1));

    expect(api.calls.find((c) => c.path === "POST /api/investigations")?.body).toEqual({
      namespace: "ai-ops-demo",
      question: "Which workloads are unhealthy, and why?",
      namespace_wide: true,
    });
  });

  it("does not create twice on a double click", async () => {
    api.on("POST /api/investigations", async () => {
      await new Promise((resolve) => setTimeout(resolve, 30));
      return { status: 201, body: record };
    });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.type(await screen.findByLabelText("Workload name"), "bad-readiness");
    const button = screen.getByRole("button", { name: "Investigate" });
    await user.dblClick(button);

    await waitFor(() => expect(api.count(`POST /api/investigations/${ID}/execute`)).toBe(1));
    expect(api.count("POST /api/investigations")).toBe(1);
  });

  it.each([
    ["ambiguous_scope", 422],
    ["multiple_targets", 422],
    ["target_not_bindable", 422],
  ])("explains a fixed rejection (%s) and does not execute", async (code) => {
    api.on("POST /api/investigations", { status: 422, body: { detail: SCOPE_MESSAGES[code] } });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.type(await screen.findByLabelText("Workload name"), "bad-readiness");
    await user.click(screen.getByRole("button", { name: "Investigate" }));

    expect(await screen.findByText(SCOPE_MESSAGES[code] as string)).toBeInTheDocument();
    expect(api.count(`POST /api/investigations/${ID}/execute`)).toBe(0);
    // The form is usable again, with the user's input intact.
    expect(screen.getByLabelText("Workload name")).toHaveValue("bad-readiness");
  });

  it("explains an unauthorized namespace", async () => {
    api.on("POST /api/investigations", { status: 403, body: { detail: "Namespace access denied." } });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.type(await screen.findByLabelText("Workload name"), "x1");
    await user.click(screen.getByRole("button", { name: "Investigate" }));

    expect(await screen.findByText(/access denied/i)).toBeInTheDocument();
  });

  it("never retries a create whose response was lost and warns about duplicates", async () => {
    let attempts = 0;
    api.on("POST /api/investigations", () => {
      attempts += 1;
      throw new TypeError("network down");
    });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.type(await screen.findByLabelText("Workload name"), "bad-readiness");
    await user.click(screen.getByRole("button", { name: "Investigate" }));

    expect(await screen.findByText("We could not confirm whether the investigation was created")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "history" })).toHaveAttribute("href", "/investigations");
    expect(attempts).toBe(1);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(attempts).toBe(1);
  });
});
