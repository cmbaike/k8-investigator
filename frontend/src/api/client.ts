import { knownScopeMessage } from "./scopeMessages";
import { knownHealthMessage } from "./healthMessages";

export type ApiErrorKind =
  | "network"
  | "timeout"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rejected"
  | "invalid"
  | "rate_limited"
  | "server"
  | "unexpected";

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | null;

  constructor(kind: ApiErrorKind, message: string, status: number | null = null) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

export const DEFAULT_TIMEOUT_MS = 15_000;
// Execution is a single synchronous request on the server (lease: 120 s).
export const EXECUTE_TIMEOUT_MS = 180_000;

interface RequestOptions {
  method?: "GET" | "POST";
  body?: unknown;
  form?: FormData;
  timeoutMs?: number;
  signal?: AbortSignal;
}

function statusMessage(status: number, detail: unknown): { kind: ApiErrorKind; message: string } {
  const health = knownHealthMessage(detail);
  if (health && status === 404) return { kind: "not_found", message: health };
  if (health && status === 403) return { kind: "forbidden", message: health };
  if (health && status === 422) return { kind: "rejected", message: health };

  switch (status) {
    case 403:
      return {
        kind: "forbidden",
        message: "That namespace is not available in this demo.",
      };
    case 404:
      return { kind: "not_found", message: "Not found." };
    case 409:
      return {
        kind: "conflict",
        message: "The investigation is not in a state that allows this action.",
      };
    case 422: {
      const known = knownScopeMessage(detail);
      return {
        kind: "rejected",
        message: known ?? "The request was not accepted. Check the namespace, target and question.",
      };
    }
    case 400:
      return { kind: "invalid", message: "The request was not accepted." };
    case 413:
      return { kind: "invalid", message: "The upload is too large." };
    case 415:
      return { kind: "invalid", message: "That file type is not supported." };
    case 429:
      return { kind: "rate_limited", message: "Too many attempts. Wait a few minutes and try again." };
    case 503:
      return { kind: "server", message: "A required service is unavailable." };
    case 504:
      return { kind: "timeout", message: "The server took too long to respond." };
    default:
      return status >= 500
        ? { kind: "server", message: `The server reported an error (HTTP ${status}).` }
        : { kind: "unexpected", message: `Unexpected response (HTTP ${status}).` };
  }
}

export async function api<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort("timeout"), options.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  options.signal?.addEventListener("abort", () => controller.abort(options.signal?.reason));

  const headers: Record<string, string> = { Accept: "application/json" };

  if (options.body !== undefined && options.form === undefined) headers["Content-Type"] = "application/json";

  let response: Response;

  try {
    response = await fetch(`/api${path}`, {
      method,
      headers,
      credentials: "same-origin",
      cache: "no-store",
      body:
        options.form !== undefined
          ? options.form
          : options.body === undefined
            ? undefined
            : JSON.stringify(options.body),
      signal: controller.signal,
    });
  } catch {
    if (controller.signal.aborted && controller.signal.reason === "timeout") {
      throw new ApiError("timeout", "The request timed out.");
    }

    if (options.signal?.aborted) throw new ApiError("network", "The request was cancelled.");

    throw new ApiError("network", "The server is unreachable. Check that the API is running.");
  } finally {
    clearTimeout(timeout);
  }

  if (response.ok) {
    if (response.status === 204) return undefined as T;

    try {
      return (await response.json()) as T;
    } catch {
      throw new ApiError("unexpected", "The server returned an unreadable response.", response.status);
    }
  }

  let detail: unknown = null;

  try {
    detail = ((await response.json()) as { detail?: unknown }).detail;
  } catch {
    // Body is never shown; only the status and the fixed scope messages are.
  }

  const { kind, message } = statusMessage(response.status, detail);

  throw new ApiError(kind, message, response.status);
}
