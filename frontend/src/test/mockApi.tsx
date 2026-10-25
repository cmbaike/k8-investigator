import { QueryClient } from "@tanstack/react-query";
import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Providers } from "@/app/providers";
import { AppRoutes } from "@/app/routes";
import { resetExecutionStateForTests } from "@/features/investigations/execution";
import { ACCESS } from "./fixtures";

type Response_ = { status?: number; body?: unknown };
type Handler = (request: { url: URL; init: RequestInit | undefined }) => Response_ | Promise<Response_>;

export interface MockApi {
  on: (route: string, handler: Handler | Response_) => void;
  calls: { method: string; path: string; body: unknown; headers: Record<string, string> }[];
  count: (route: string) => number;
}

// Replaces fetch with an in-memory router keyed by "METHOD /api/path" (query
// string ignored). An unregistered route fails the test loudly.
export function installMockApi(): MockApi {
  const routes = new Map<string, Handler>();
  const calls: MockApi["calls"] = [];

  const fetchMock = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const url = new URL(String(input), "http://localhost");
    const method = (init?.method ?? "GET").toUpperCase();
    const key = `${method} ${url.pathname}`;
    const headers = Object.fromEntries(Object.entries((init?.headers ?? {}) as Record<string, string>));

    let body: unknown;

    if (typeof init?.body === "string") {
      try {
        body = JSON.parse(init.body);
      } catch {
        body = init.body;
      }
    } else if (init?.body != null) {
      body = init.body;
    }

    calls.push({ method, path: key, body, headers });

    const handler = routes.get(key);

    if (!handler) throw new Error(`Unmocked request: ${key}`);

    const reply = await handler({ url, init });
    const status = reply.status ?? 200;

    return new Response(status === 204 ? null : JSON.stringify(reply.body ?? {}), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  };

  globalThis.fetch = fetchMock as typeof fetch;

  return {
    calls,
    on(route, handler) {
      routes.set(route, typeof handler === "function" ? handler : () => handler);
    },
    count: (route) => calls.filter((call) => call.path === route).length,
  };
}

export function resetApp() {
  resetExecutionStateForTests();
}

export function renderApp(route: string, api: MockApi) {
  api.on("GET /api/access", { body: ACCESS });

  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: 0 }, mutations: { retry: false } },
  });

  return {
    client,
    ...render(
      <MemoryRouter initialEntries={[route]}>
        <Providers client={client}>
          <AppRoutes />
        </Providers>
      </MemoryRouter>,
    ),
  };
}
