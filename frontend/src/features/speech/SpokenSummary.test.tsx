import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ID, audit, report, summary } from "@/test/fixtures";
import { installMockApi, renderApp, resetApp, type MockApi } from "@/test/mockApi";

class FakeAudio {
  src = "";
  paused = true;
  currentTime = 0;
  onended: (() => void) | null = null;
  onerror: (() => void) | null = null;
  plays = 0;

  play(): Promise<void> {
    this.paused = false;
    this.plays += 1;
    return Promise.resolve();
  }

  pause(): void {
    this.paused = true;
  }
}

let api: MockApi;
const created: FakeAudio[] = [];
const briefing = `GET /api/investigations/${ID}/briefing`;

beforeEach(() => {
  created.length = 0;
  vi.stubGlobal(
    "Audio",
    class {
      constructor() {
        const audio = new FakeAudio();
        created.push(audio);
        return audio;
      }
    },
  );
  window.localStorage.removeItem("pai-spoken");
  api = installMockApi();
  api.on("GET /api/health", { body: { status: "ok", database: true } });
  api.on(`GET /api/investigations/${ID}/summary`, { body: summary() });
  api.on(`GET /api/investigations/${ID}/report`, { body: report() });
  api.on(`GET /api/investigations/${ID}/audit`, { body: audit() });
});

afterEach(() => {
  window.localStorage.removeItem("pai-spoken");
  vi.unstubAllGlobals();
  resetApp();
});

describe("spoken summary playback", () => {
  it("does not play or fetch audio until Listen is chosen", async () => {
    renderApp(`/investigations/${ID}`, api);

    expect(await screen.findByRole("button", { name: "Listen to summary" })).toBeInTheDocument();
    expect(created).toHaveLength(0);
    expect(api.count(briefing)).toBe(0);
    expect(screen.getByRole("region", { name: "Primary verified finding" })).toBeInTheDocument();
  });

  it("plays, pauses, resumes, stops and replays, and shows the exact briefing", async () => {
    const text =
      "Container app is running but not ready. Kubernetes reports the container running and its readiness false. A possible explanation is that the probe path may be wrong.";
    api.on(briefing, { body: { text, speech_available: true } });
    const user = userEvent.setup();
    renderApp(`/investigations/${ID}`, api);

    await user.click(await screen.findByRole("button", { name: "Listen to summary" }));

    await waitFor(() => expect(screen.getByRole("button", { name: "Pause" })).toBeEnabled());
    expect(created).toHaveLength(1);
    expect(created[0]?.src).toBe(`/api/investigations/${ID}/briefing/audio`);
    expect(created[0]?.src).not.toMatch(/api[_-]?key|PRIVATE_AI/i);
    expect(created[0]?.plays).toBe(1);
    expect(await screen.findByText(text)).toBeInTheDocument();
    expect(screen.queryByText(/Spoken briefing/)).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Pause" }));
    expect(created[0]?.paused).toBe(true);

    await user.click(screen.getByRole("button", { name: "Resume" }));
    await waitFor(() => expect(created[0]?.paused).toBe(false));
    expect(created[0]?.plays).toBe(2);

    await user.click(screen.getByRole("button", { name: "Stop" }));
    expect(created[0]?.paused).toBe(true);
    expect(created[0]?.currentTime).toBe(0);

    await user.click(screen.getByRole("button", { name: "Replay" }));
    await waitFor(() => expect(created[0]?.plays).toBe(3));
    expect(screen.getByRole("region", { name: "Primary verified finding" })).toBeInTheDocument();
  });

  it("keeps the report when speech synthesis is unavailable", async () => {
    api.on(briefing, {
      body: {
        text: "Container app is running but not ready. The underlying cause hasn't been confirmed.",
        speech_available: false,
      },
    });
    const user = userEvent.setup();
    renderApp(`/investigations/${ID}`, api);

    await user.click(await screen.findByRole("button", { name: "Listen to summary" }));

    expect(await screen.findByRole("alert")).toHaveTextContent(/unavailable/i);
    expect(screen.getByText("Container app is running but not ready. The underlying cause hasn't been confirmed.")).toBeInTheDocument();
    expect(created[0]?.paused).toBe(true);
    expect(screen.getByRole("region", { name: "Primary verified finding" })).toBeInTheDocument();
  });

  it("can turn spoken responses off and still show the briefing text", async () => {
    api.on(briefing, {
      body: { text: "The investigation failed. No finding was established.", speech_available: true },
    });
    const user = userEvent.setup();
    renderApp(`/investigations/${ID}`, api);

    await user.click(await screen.findByRole("checkbox", { name: "Spoken responses" }));

    expect(screen.queryByRole("button", { name: "Listen to summary" })).not.toBeInTheDocument();
    expect(created).toHaveLength(0);

    await user.click(screen.getByRole("button", { name: "Show briefing text" }));

    expect(await screen.findByText("The investigation failed. No finding was established.")).toBeInTheDocument();
    expect(created).toHaveLength(0);
  });
});
