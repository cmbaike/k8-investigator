import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { SCOPE_MESSAGES } from "@/api/scopeMessages";
import { ID, summary, audit } from "@/test/fixtures";
import { installMockApi, renderApp, resetApp, type MockApi } from "@/test/mockApi";
import { microphoneMessage, voiceCapture } from "./record";

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
const originalRecord = voiceCapture.record;

beforeEach(() => {
  api = installMockApi();
  api.on("GET /api/health", { body: { status: "ok", database: true } });
  api.on(`GET /api/investigations/${ID}/summary`, {
    body: summary({ status: "running", finished_at: null, duration_seconds: null, primary_finding: null, finding_counts: null }),
  });
  api.on(`GET /api/investigations/${ID}/audit`, { body: audit({ events: [] }) });
  api.on(`POST /api/investigations/${ID}/execute`, { body: { ...record, status: "completed" } });
  api.on("POST /api/speech/proposal", ({ init }) => {
    const body = JSON.parse(String(init?.body)) as { transcript: string; namespace: string };
    const text = body.transcript;

    if (text.includes("namespace health")) {
      return { body: { outcome: "namespace", name: null, kind: null, code: null } };
    }

    if (text.includes("Why is it failing")) {
      return { body: { outcome: "clarify", name: null, kind: null, code: "scope_unspecified" } };
    }

    const name = text.includes("bad-readiness") ? "bad-readiness" : text.includes("bad-readyness") ? "bad-readyness" : null;

    if (!name) return { body: { outcome: "clarify", name: null, kind: null, code: "scope_unspecified" } };

    return {
      body: {
        outcome: "workload",
        name,
        kind: /\bpod\//i.test(text) ? "Pod" : null,
        code: null,
      },
    };
  });
});

afterEach(() => {
  voiceCapture.record = originalRecord;
  resetApp();
});

function wav(): Blob {
  return new Blob([new Uint8Array(9_000)], { type: "audio/wav" });
}

async function speak(user: ReturnType<typeof userEvent.setup>, transcript: string) {
  voiceCapture.record = async () => wav();
  api.on("POST /api/speech/transcribe", { body: { transcript } });
  await user.click(await screen.findByRole("button", { name: "Speak a request" }));
  expect(await screen.findByLabelText("Recognized speech")).toHaveValue(transcript);
}

describe("microphone on the new investigation page", () => {
  it("explains a denied microphone permission and does not call the API", async () => {
    voiceCapture.record = () => Promise.reject(Object.assign(new Error("denied"), { name: "NotAllowedError" }));
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.click(await screen.findByRole("button", { name: "Speak a request" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/permission was denied/i);
    expect(microphoneMessage(Object.assign(new Error("no"), { name: "NotAllowedError" }))).toMatch(/denied/i);
    expect(api.count("POST /api/speech/transcribe")).toBe(0);
    expect(api.count("POST /api/speech/proposal")).toBe(0);
    expect(api.count("POST /api/investigations")).toBe(0);
  });

  it("reviews a targeted transcript and fills the form only after confirmation", async () => {
    const user = userEvent.setup();
    renderApp("/investigations/new", api);
    const transcript = "Investigate why the bad-readiness workload is failing in ai-ops-demo.";

    await speak(user, transcript);

    expect(screen.getByLabelText("Workload name")).toHaveValue("");
    expect(screen.getByLabelText("Question")).toHaveValue("Why is this workload unhealthy?");
    expect(await screen.findByText(/Proposed: workload bad-readiness in ai-ops-demo/)).toBeInTheDocument();
    expect(api.count("POST /api/investigations")).toBe(0);
    expect(api.calls.find((call) => call.path === "POST /api/speech/proposal")?.body).toMatchObject({
      transcript,
      namespace: "ai-ops-demo",
    });

    await user.click(screen.getByRole("button", { name: "Use this request" }));

    expect(screen.getByLabelText("Workload name")).toHaveValue("bad-readiness");
    expect(screen.getByLabelText("Question")).toHaveValue(transcript);
    expect(screen.getByLabelText("One workload")).toBeChecked();
    expect(api.count("POST /api/investigations")).toBe(0);
  });

  it("proposes the selected namespace for an explicit namespace-wide request", async () => {
    const user = userEvent.setup();
    renderApp("/investigations/new", api);
    const transcript = "Investigate the namespace health";

    await speak(user, transcript);

    expect(screen.getByLabelText("One workload")).toBeChecked();
    expect(screen.getByLabelText("Workload name")).toHaveValue("");
    expect(await screen.findByText(/Proposed: the whole namespace ai-ops-demo/)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Use this request" }));

    expect(screen.getByLabelText("Whole namespace (broad)")).toBeChecked();
    expect(screen.queryByLabelText("Workload name")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Question")).toHaveValue(transcript);
    expect(api.count("POST /api/investigations")).toBe(0);
  });

  it("asks for clarification instead of widening an ambiguous request", async () => {
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await speak(user, "Why is it failing?");

    expect(await screen.findByText(SCOPE_MESSAGES.scope_unspecified as string)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Use this request" })).toBeDisabled();
    expect(screen.getByLabelText("One workload")).toBeChecked();
    expect(screen.getByLabelText("Workload name")).toHaveValue("");
    expect(screen.getByLabelText("Question")).toHaveValue("Why is this workload unhealthy?");
    expect(api.count("POST /api/investigations")).toBe(0);
  });

  it("keeps a misheard name editable and submits only the corrected target", async () => {
    const user = userEvent.setup();
    renderApp("/investigations/new", api);
    api.on("POST /api/investigations", { status: 201, body: record });

    await speak(user, "Investigate why the bad-readyness workload is failing in ai-ops-demo.");
    expect(await screen.findByText(/Proposed: workload bad-readyness/)).toBeInTheDocument();
    expect(screen.getByLabelText("Workload name")).toHaveValue("");

    const speech = screen.getByLabelText("Recognized speech");
    await user.clear(speech);
    await user.type(speech, "Why is bad-readiness failing?");
    expect(await screen.findByText(/Proposed: workload bad-readiness in ai-ops-demo/)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Use this request" }));

    expect(screen.getByLabelText("Workload name")).toHaveValue("bad-readiness");
    const name = screen.getByLabelText("Workload name");
    await user.clear(name);
    await user.type(name, "bad-readiness");
    await user.click(screen.getByRole("button", { name: "Investigate" }));

    await waitFor(() => expect(api.count("POST /api/investigations")).toBe(1));
    expect(api.calls.find((call) => call.path === "POST /api/investigations")?.body).toMatchObject({
      namespace: "ai-ops-demo",
      question: "Why is bad-readiness failing?",
      target: { kind: "Deployment", name: "bad-readiness" },
    });
  });

  it("switches from a namespace-wide proposal to a targeted one only when confirmed", async () => {
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await speak(user, "Investigate the namespace health");
    await user.click(await screen.findByRole("button", { name: "Use this request" }));
    expect(screen.getByLabelText("Whole namespace (broad)")).toBeChecked();

    const speech = screen.getByLabelText("Recognized speech");
    await user.clear(speech);
    await user.type(speech, "Why is bad-readiness failing?");
    expect(screen.getByLabelText("Whole namespace (broad)")).toBeChecked();
    expect(screen.queryByLabelText("Workload name")).not.toBeInTheDocument();

    await user.click(await screen.findByRole("button", { name: "Use this request" }));

    expect(screen.getByLabelText("One workload")).toBeChecked();
    expect(screen.getByLabelText("Workload name")).toHaveValue("bad-readiness");
    expect(screen.getByLabelText("Question")).toHaveValue("Why is bad-readiness failing?");
    expect(api.count("POST /api/investigations")).toBe(0);
  });

  it("rejects an empty recording before upload", async () => {
    voiceCapture.record = async () => new Blob([new Uint8Array(32)], { type: "audio/wav" });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.click(await screen.findByRole("button", { name: "Speak a request" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/empty/i);
    expect(api.count("POST /api/speech/transcribe")).toBe(0);
    expect(api.count("POST /api/speech/proposal")).toBe(0);
  });

  it("reports an oversized upload and an unavailable transcriber without blocking the form", async () => {
    voiceCapture.record = async () => wav();
    api.on("POST /api/speech/transcribe", { status: 413, body: { detail: "raw bytes" } });
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.click(await screen.findByRole("button", { name: "Speak a request" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/too large/i);
    expect(screen.getByRole("alert")).not.toHaveTextContent("raw bytes");

    api.on("POST /api/speech/transcribe", { status: 503, body: { detail: "stack trace" } });
    await user.click(screen.getByRole("button", { name: "Speak a request" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/unavailable/i);
    expect(screen.getByRole("alert")).not.toHaveTextContent("stack trace");
    expect(screen.getByRole("button", { name: "Investigate" })).toBeEnabled();
    expect(api.count("POST /api/speech/proposal")).toBe(0);
  });

  it("clears a workload-name error after a valid change or a confirmed namespace-wide request", async () => {
    const user = userEvent.setup();
    renderApp("/investigations/new", api);

    await user.click(await screen.findByRole("button", { name: "Investigate" }));
    expect(await screen.findByText("Enter the exact workload name.")).toBeInTheDocument();

    await user.type(screen.getByLabelText("Workload name"), "bad-readiness");
    expect(screen.queryByText("Enter the exact workload name.")).not.toBeInTheDocument();

    await user.clear(screen.getByLabelText("Workload name"));
    await user.click(screen.getByRole("button", { name: "Investigate" }));
    expect(await screen.findByText("Enter the exact workload name.")).toBeInTheDocument();

    await speak(user, "Investigate the namespace health");
    await user.click(await screen.findByRole("button", { name: "Use this request" }));

    expect(screen.queryByText("Enter the exact workload name.")).not.toBeInTheDocument();
    expect(screen.queryByLabelText("Workload name")).not.toBeInTheDocument();
  });
});
