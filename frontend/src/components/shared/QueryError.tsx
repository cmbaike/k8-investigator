import { RefreshCw } from "lucide-react";
import { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Callout } from "./Callout";

export function QueryError({ error, onRetry, title = "Could not load this data" }: { error: unknown; onRetry?: () => void; title?: string }) {
  const message = error instanceof ApiError ? error.message : "An unexpected error occurred.";

  return (
    <Callout
      tone="error"
      title={title}
      action={
        onRetry ? (
          <Button size="sm" onClick={onRetry}>
            <RefreshCw aria-hidden="true" className="size-3.5" />
            Retry
          </Button>
        ) : undefined
      }
    >
      {message}
    </Callout>
  );
}
