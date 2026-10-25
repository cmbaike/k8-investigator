import type { QueryClient } from "@tanstack/react-query";
import { useSyncExternalStore } from "react";
import { ApiError } from "@/api/client";
import { endpoints } from "@/api/endpoints";

// Execution is one long synchronous request on the server. It is started here,
// outside any component, so that navigating to the detail page does not cancel
// it, and it is started AT MOST ONCE per investigation from this tab: there is
// no automatic retry. The server's status (polled) is always the authority.

export type ExecutionState =
  | { phase: "requested" }
  | { phase: "finished" }
  | { phase: "failed"; message: string };

const states = new Map<string, ExecutionState>();
const listeners = new Set<() => void>();

function publish(id: string, state: ExecutionState) {
  states.set(id, state);
  listeners.forEach((listener) => listener());
}

export function startExecution(queryClient: QueryClient, id: string): void {
  if (states.has(id)) return;

  publish(id, { phase: "requested" });

  void endpoints
    .execute(id)
    .then(() => publish(id, { phase: "finished" }))
    .catch((error: unknown) => {
      const message =
        error instanceof ApiError
          ? error.kind === "timeout" || error.kind === "network"
            ? "The execute request did not return. The investigation may still be running; the status below is read from the server."
            : error.message
          : "The execute request failed.";
      publish(id, { phase: "failed", message });
    })
    .finally(() => {
      void queryClient.invalidateQueries({ queryKey: ["investigation", id] });
      void queryClient.invalidateQueries({ queryKey: ["investigations"] });
    });
}

export function useExecutionState(id: string): ExecutionState | undefined {
  return useSyncExternalStore(
    (listener) => {
      listeners.add(listener);

      return () => listeners.delete(listener);
    },
    () => states.get(id),
  );
}

export function resetExecutionStateForTests(): void {
  states.clear();
}
