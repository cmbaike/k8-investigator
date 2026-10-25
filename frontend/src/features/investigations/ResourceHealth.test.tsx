import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ID, summary } from "@/test/fixtures";
import { installMockApi, renderApp, resetApp, type MockApi } from "@/test/mockApi";
import type { ResourceHealth } from "@/types/api";

let api: MockApi;

const record = {
  investigation_id: ID,
  authorized_namespace: "ai-ops-demo",
  status: "pending",
  created_at: "2026-10-18T10:00:00Z",
  started_at: null,
  finished_at: null,
  stop_reason: null,
  user_text: "q",
  max_steps: 6,
};

function health(name: string, category: ResourceHealth["category"] = "unhealthy"): ResourceHealth {
  return {
    resource: {
      namespace: "ai-ops-demo",
      kind: "Deployment",
      name,
      uid: "11111111-1111-1111-1111-111111111111",
    },
    category,
    signals:
      category === "healthy"
        ? []
        : category === "unknown"
          ? []
          : [{ code: "image_pull_backoff", label: "Image pull is backing off" }],
    workload: { desired: 2, ready: category === "healthy" ? 2 : 1, available: 1, updated: 1 },
    pods: [
      {
        name: `${name}-5d6b7c8d9-k7m2p`,
        uid: "33333333-3333-3333-3333-333333333333",
        phase: "Pending",
        ready: false,
        category,
        signals: [],
        containers: [
          {
            name: "app",
            ready: false,
            state: "waiting",
            waiting_reason: "ImagePullBackOff",
            last_termination_reason: null,
            last_exit_code: null,
            restart_count: 0,
            configured_memory_request: null,
            configured_memory_limit: "32Mi",
          },
        ],
      },
    ],
    coverage: {
      discovered: category === "unknown" ? 3 : 1,
      examined: 1,
      complete: category !== "unknown",
      summary: category === "unknown" ? "Inspected 1 of 3 pods." : "Inspected 1 of 1 pods.",
      limitations:
        category === "unknown"
          ? [{ code: "pod_cap", label: "Only the first matching pods were inspected." }]
          : [],
    },
    observed_at: "2026-10-20T11:00:00Z",
    ttl_seconds: 30,
    snapshot: "point_in_time",
  };
}

beforeEach(() => {
  api = installMockApi();
  api.on("GET /api/health", { body: { status: "ok", database: true } });
});
afterEach(resetApp);

async function choose(user: ReturnType<typeof userEvent.setup>, name: string) {
  await user.type(await screen.findByLabelText("Workload name"), name);
}

describe("Resource health", () => {
  it("shows the snapshot for the selected resource, coverage, and no mutation controls", async () => {
    api.on("GET /api/resources/health", { body: health("bad-readiness") });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await choose(user, "bad-readiness");
    await user.click(screen.getByRole("button", { name: "Check health" }));

    expect(await screen.findByText("Unhealthy")).toBeInTheDocument();
    expect(screen.getByText("Deployment bad-readiness")).toBeInTheDocument();
    expect(screen.getByText("Image pull is backing off")).toBeInTheDocument();
    expect(screen.getByText("1 ready of 2 desired")).toBeInTheDocument();
    expect(screen.getByText("Inspected 1 of 1 pods.")).toBeInTheDocument();
    expect(screen.getByText(/point-in-time snapshot/i)).toBeInTheDocument();
    expect(api.count("POST /api/investigations")).toBe(0);
    expect(screen.queryByRole("button", { name: /restart|delete|scale|patch/i })).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Pod and container state" }));
    expect(screen.getByText("bad-readiness-5d6b7c8d9-k7m2p")).toBeInTheDocument();
    expect(screen.getByText(/configured memory limit 32Mi/)).toBeInTheDocument();
    expect(screen.queryByText(/measured usage/i)).not.toBeInTheDocument();
  });

  it("distinguishes unknown from no issue established", async () => {
    api.on("GET /api/resources/health", { body: health("quiet-api", "unknown") });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);
    await choose(user, "quiet-api");
    await user.click(screen.getByRole("button", { name: "Check health" }));

    expect(await screen.findByText("Unknown")).toBeInTheDocument();
    expect(screen.getByText("Health could not be established from this snapshot.")).toBeInTheDocument();
    expect(screen.queryByText("No issue was established in this snapshot.")).not.toBeInTheDocument();
    expect(screen.getByText("Inspected 1 of 3 pods.")).toBeInTheDocument();
    expect(screen.getByText("Only the first matching pods were inspected.")).toBeInTheDocument();
  });

  it("shows a not-found error and does not keep a previous snapshot", async () => {
    let name = "bad-readiness";
    api.on("GET /api/resources/health", () =>
      name === "missing-api"
        ? { status: 404, body: { detail: "not_found" } }
        : { body: health("bad-readiness") },
    );
    const user = userEvent.setup();
    renderApp("/investigations/new", api);
    await choose(user, "bad-readiness");
    await user.click(screen.getByRole("button", { name: "Check health" }));
    expect(await screen.findByText("Unhealthy")).toBeInTheDocument();

    name = "missing-api";
    await user.clear(screen.getByLabelText("Workload name"));
    await user.type(screen.getByLabelText("Workload name"), "missing-api");
    expect(screen.queryByText("Unhealthy")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check health" }));
    expect(await screen.findByText(/No other workloads were checked/)).toBeInTheDocument();
    expect(screen.queryByText("Unhealthy")).not.toBeInTheDocument();
  });

  it("explains an unsupported kind without starting an investigation", async () => {
    api.on("GET /api/resources/health", ({ url }) =>
      url.searchParams.get("kind") === "StatefulSet"
        ? { status: 422, body: { detail: "unsupported_kind" } }
        : { status: 403, body: { detail: "namespace_denied" } },
    );
    const user = userEvent.setup();
    renderApp("/investigations/new", api);
    await choose(user, "bad-readiness");
    await user.selectOptions(screen.getByLabelText("Resource kind"), "StatefulSet");
    await user.click(screen.getByRole("button", { name: "Check health" }));
    expect(await screen.findByText(/Deployment and Pod only/)).toBeInTheDocument();
  });

  it("drops a slow response after the selection changes and refreshes the new one", async () => {
    let release: (() => void) | undefined;
    api.on("GET /api/resources/health", ({ url }) => {
      const selected = url.searchParams.get("name");
      if (selected === "first-api") {
        return new Promise((resolve) => {
          release = () => resolve({ body: health("first-api") });
        });
      }
      return { body: health("second-api", "healthy") };
    });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);
    await choose(user, "first-api");
    await user.click(screen.getByRole("button", { name: "Check health" }));
    expect(await screen.findByText("Checking Deployment first-api…")).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Workload name"));
    await user.type(screen.getByLabelText("Workload name"), "second-api");
    expect(screen.queryByText("Checking Deployment first-api…")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Check health" }));
    expect(await screen.findByText("Healthy")).toBeInTheDocument();
    expect(screen.getByText("No issue was established in this snapshot.")).toBeInTheDocument();

    release?.();
    await waitFor(() => expect(screen.queryByText("Image pull is backing off")).not.toBeInTheDocument());
    expect(screen.getByText("Deployment second-api")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Refresh" }));
    await waitFor(() => expect(api.count("GET /api/resources/health")).toBe(3));
  });

  it("marks an old snapshot stale without checking again", async () => {
    api.on("GET /api/resources/health", {
      body: { ...health("bad-readiness", "healthy"), observed_at: "2020-01-01T00:00:00Z", ttl_seconds: 1 },
    });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);
    await choose(user, "bad-readiness");
    await user.click(screen.getByRole("button", { name: "Check health" }));
    expect(await screen.findByText("Snapshot is out of date")).toBeInTheDocument();
    expect(api.count("GET /api/resources/health")).toBe(1);
  });

  it("starts an investigation only after confirming the exact selected target", async () => {
    api.on("POST /api/investigations", { status: 201, body: record });
    api.on(`GET /api/investigations/${ID}/summary`, {
      body: summary({ status: "running", finished_at: null, duration_seconds: null, primary_finding: null, finding_counts: null }),
    });
    api.on(`GET /api/investigations/${ID}/audit`, { body: { investigation_id: ID, events: [], truncated: false } });
    api.on(`POST /api/investigations/${ID}/execute`, { body: { ...record, status: "completed" } });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);
    await choose(user, "bad-readiness");

    await user.click(screen.getByRole("button", { name: "Investigate with AI" }));
    expect(api.count("POST /api/investigations")).toBe(0);
    expect(api.count("GET /api/resources/health")).toBe(0);

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(api.count("POST /api/investigations")).toBe(0);

    await user.click(screen.getByRole("button", { name: "Investigate with AI" }));
    await user.click(screen.getByRole("button", { name: "Start investigation" }));
    await waitFor(() => expect(api.count("POST /api/investigations")).toBe(1));
    expect(api.calls.find((call) => call.path === "POST /api/investigations")?.body).toEqual({
      namespace: "ai-ops-demo",
      question: "Why is this workload unhealthy?",
      target: { kind: "Deployment", name: "bad-readiness" },
    });
  });
});
