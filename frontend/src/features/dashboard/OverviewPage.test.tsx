import { screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ApiError } from "@/api/client";
import { ID, STATS, page, summary } from "@/test/fixtures";
import { installMockApi, renderApp, resetApp, type MockApi } from "@/test/mockApi";

let api: MockApi;
beforeEach(() => {
  api = installMockApi();
  api.on("GET /api/health", { body: { status: "ok", database: true } });
});
afterEach(resetApp);

describe("Overview", () => {
  it("shows backend-derived figures and recent investigations", async () => {
    api.on("GET /api/investigations/stats", { body: STATS });
    api.on("GET /api/investigations", { body: page([summary(), summary({ investigation_id: "b", status: "failed", scope: { mode: "namespace", kind: null, name: null }, primary_finding: null, finding_counts: null })]) });
    renderApp("/", api);

    const metrics = await screen.findByRole("region", { name: "Summary" });

    expect(await within(metrics).findByText("12")).toBeInTheDocument();
    expect(within(metrics).getByText("10")).toBeInTheDocument();
    expect(within(metrics).getByText("8")).toBeInTheDocument();
    expect(within(metrics).getByText("6.5 s")).toBeInTheDocument();
    expect(await screen.findByText("Deployment/bad-readiness")).toBeInTheDocument();
    expect(screen.getByText("Container is running but not ready")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /open investigation 9acee6e5/i })).toHaveAttribute(
      "href",
      `/investigations/${ID}`,
    );
  });

  it("shows an empty state, not invented rows, when there are no investigations", async () => {
    api.on("GET /api/investigations/stats", { body: { ...STATS, total: 0, completed: 0, failed: 0, in_progress: 0, completed_with_warning_or_higher: 0, average_duration_seconds: null } });
    api.on("GET /api/investigations", { body: page([]) });
    renderApp("/", api);

    expect(await screen.findByText("No investigations have been run yet.")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
    expect(screen.getByText("—")).toBeInTheDocument();
  });

  it("shows a loading state while data is pending", async () => {
    api.on("GET /api/investigations/stats", () => new Promise(() => {}));
    api.on("GET /api/investigations", () => new Promise(() => {}));
    renderApp("/", api);

    expect(await screen.findByLabelText("Loading recent investigations")).toBeInTheDocument();
  });

  it("shows retryable errors for each failed query without echoing server text", async () => {
    api.on("GET /api/investigations/stats", { status: 500, body: { detail: "boom password=x" } });
    api.on("GET /api/investigations", { status: 500, body: {} });
    renderApp("/", api);

    const alerts = await screen.findAllByRole("alert");

    expect(alerts.length).toBeGreaterThanOrEqual(2);
    expect(document.body.textContent).not.toContain("password=x");
    expect(screen.getAllByRole("button", { name: "Retry" }).length).toBeGreaterThanOrEqual(2);
    expect(ApiError).toBeDefined();
  });
});

