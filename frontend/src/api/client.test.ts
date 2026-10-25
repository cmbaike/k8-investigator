import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { installMockApi, resetApp, type MockApi } from "@/test/mockApi";
import { ApiError } from "./client";
import { endpoints } from "./endpoints";
import { SCOPE_MESSAGES } from "./scopeMessages";

let mock: MockApi;

beforeEach(() => {
  mock = installMockApi();
});
afterEach(() => {
  resetApp();
  vi.useRealTimers();
});

describe("api client", () => {
  it("does not send an API key or an authorization header", async () => {
    mock.on("GET /api/investigations/stats", { body: {} });
    mock.on("POST /api/investigations", { status: 201, body: {} });

    await endpoints.stats();
    await endpoints.create({ namespace: "ai-ops-demo", question: "q", namespace_wide: true });

    for (const call of mock.calls) {
      expect(Object.keys(call.headers).map((name) => name.toLowerCase())).not.toContain("x-api-key");
      expect(Object.keys(call.headers).map((name) => name.toLowerCase())).not.toContain("authorization");
    }
  });

  it("shows only exact, known scope messages from a 422", async () => {
    mock.on("POST /api/investigations", { status: 422, body: { detail: SCOPE_MESSAGES.multiple_targets } });
    await expect(endpoints.create({ namespace: "n", question: "q" })).rejects.toMatchObject({
      kind: "rejected",
      message: SCOPE_MESSAGES.multiple_targets,
    });

    mock.on("POST /api/investigations", {
      status: 422,
      body: { detail: "Traceback (most recent call last): postgres://user:secret@db" },
    });
    const error = await endpoints.create({ namespace: "n", question: "q" }).catch((e: unknown) => e);

    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).message).not.toContain("secret");
    expect((error as ApiError).message).not.toContain("Traceback");
  });

  it("never echoes a server error body", async () => {
    mock.on("GET /api/investigations/stats", { status: 500, body: { detail: "psycopg.OperationalError: password=hunter2" } });
    const error = (await endpoints.stats().catch((e: unknown) => e)) as ApiError;

    expect(error.kind).toBe("server");
    expect(error.message).not.toContain("hunter2");
  });

  it("maps 403, 404, 409 and 429 to explicit kinds", async () => {
    for (const [status, kind] of [[403, "forbidden"], [404, "not_found"], [409, "conflict"], [429, "rate_limited"]] as const) {
      mock.on("GET /api/investigations/stats", { status, body: {} });
      await expect(endpoints.stats()).rejects.toMatchObject({ kind });
    }
  });

  it("reports an unreachable server and a timeout distinctly", async () => {
    globalThis.fetch = (() => Promise.reject(new TypeError("fetch failed"))) as typeof fetch;
    await expect(endpoints.stats()).rejects.toMatchObject({ kind: "network" });

    vi.useFakeTimers();
    globalThis.fetch = ((_: unknown, init?: RequestInit) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
      })) as typeof fetch;
    const pending = endpoints.stats().catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(16_000);

    expect(await pending).toMatchObject({ kind: "timeout" });
  });

  it("uses same-origin credentials and no-store caching", async () => {
    const spy = vi.fn(async () => new Response("{}", { status: 200 }));
    globalThis.fetch = spy as unknown as typeof fetch;
    await endpoints.stats();

    const init = spy.mock.calls[0] as unknown as [string, RequestInit];

    expect(init[1].credentials).toBe("same-origin");
    expect(init[1].cache).toBe("no-store");
    expect(init[0].startsWith("/api/")).toBe(true);
  });
});
