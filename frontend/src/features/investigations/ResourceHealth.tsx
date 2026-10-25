import { useEffect, useRef, useState } from "react";
import { ApiError } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import { formatCompact } from "@/components/shared/format";
import { Callout } from "@/components/shared/Callout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Disclosure } from "@/components/ui/disclosure";
import type { ResourceHealth, ResourceHealthCategory, TargetKind } from "@/types/api";

const CATEGORY_TONE = {
  healthy: "ok",
  degraded: "warning",
  unhealthy: "critical",
  unknown: "info",
} as const;

const CATEGORY_LABEL: Record<ResourceHealthCategory, string> = {
  healthy: "Healthy",
  degraded: "Degraded",
  unhealthy: "Unhealthy",
  unknown: "Unknown",
};

function categorySentence(category: ResourceHealthCategory): string | null {
  if (category === "healthy") return "No issue was established in this snapshot.";
  if (category === "unknown") return "Health could not be established from this snapshot.";
  return null;
}

export function ResourceHealthPanel({
  namespace,
  kind,
  name,
  scope,
  nameValid,
  onInvestigate,
}: {
  namespace: string;
  kind: TargetKind;
  name: string;
  scope: "workload" | "namespace";
  nameValid: boolean;
  onInvestigate: () => void;
}) {
  const generation = useRef(0);
  const abortRef = useRef<AbortController | null>(null);
  const inflight = useRef(false);
  const [phase, setPhase] = useState<"idle" | "loading">("idle");
  const [snapshot, setSnapshot] = useState<ResourceHealth | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [stale, setStale] = useState(false);
  const [confirming, setConfirming] = useState(false);

  useEffect(() => {
    generation.current += 1;
    abortRef.current?.abort();
    inflight.current = false;
    setSnapshot(null);
    setError(null);
    setStale(false);
    setConfirming(false);
    setPhase("idle");
  }, [namespace, kind, name, scope]);

  useEffect(() => {
    if (!snapshot) return;
    const elapsed = Date.now() - new Date(snapshot.observed_at).getTime();
    const wait = Math.max(0, snapshot.ttl_seconds * 1000 - elapsed);
    const timer = window.setTimeout(() => setStale(true), wait);
    return () => window.clearTimeout(timer);
  }, [snapshot]);

  function load() {
    if (!nameValid || scope !== "workload" || inflight.current) return;

    const token = ++generation.current;
    const target = { namespace, kind, name };
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    inflight.current = true;
    setPhase("loading");
    setError(null);
    setStale(false);
    setConfirming(false);

    void endpoints
      .resourceHealth(target, controller.signal)
      .then((result) => {
        if (token !== generation.current) return;
        const same =
          result.resource.namespace === target.namespace &&
          result.resource.kind === target.kind &&
          result.resource.name === target.name;
        if (!same) {
          setSnapshot(null);
          setError(new ApiError("unexpected", "The health response did not match the selected resource."));
          return;
        }
        setSnapshot(result);
      })
      .catch((caught: unknown) => {
        if (token !== generation.current) return;
        if (controller.signal.aborted) return;
        setSnapshot(null);
        setError(caught instanceof ApiError ? caught : new ApiError("unexpected", "The health check failed."));
      })
      .finally(() => {
        if (token === generation.current) {
          inflight.current = false;
          setPhase("idle");
        }
      });
  }

  if (scope !== "workload") {
    return (
      <p className="text-xs text-muted">
        A health check applies to one selected workload. It does not describe the namespace.
      </p>
    );
  }

  const sentence = snapshot ? categorySentence(snapshot.category) : null;
  const counts = snapshot?.workload;
  const countText =
    counts && counts.desired !== null && counts.ready !== null
      ? `${counts.ready} ready of ${counts.desired} desired`
      : null;

  return (
    <section aria-label="Resource health" className="space-y-3 rounded-md border border-border bg-surface-2/40 px-3 py-3">
      <div className="flex flex-wrap items-center gap-2">
        <Button type="button" size="sm" onClick={load} disabled={!nameValid || phase === "loading"}>
          {phase === "loading" ? "Checking…" : "Check health"}
        </Button>
        <Button type="button" size="sm" variant="ghost" onClick={load} disabled={!snapshot || phase === "loading"}>
          Refresh
        </Button>
        <Button
          type="button"
          size="sm"
          variant="ghost"
          disabled={!nameValid}
          onClick={() => setConfirming(true)}
        >
          Investigate with AI
        </Button>
      </div>
      <p className="text-xs text-muted">
        Point-in-time snapshot of this resource only. Not a monitor, and not an availability target.
      </p>

      {phase === "loading" ? (
        <p className="text-[13px] text-muted" role="status">
          Checking {kind} {name}…
        </p>
      ) : null}

      {error ? (
        <Callout tone="error" title="Health check failed">
          {error.message}
        </Callout>
      ) : null}

      {snapshot ? (
        <div className="space-y-2" aria-live="polite">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={CATEGORY_TONE[snapshot.category]}>{CATEGORY_LABEL[snapshot.category]}</Badge>
            <span className="text-[13px] font-medium">
              {snapshot.resource.kind} {snapshot.resource.name}
            </span>
          </div>
          <p className="text-xs text-muted">Last checked {formatCompact(snapshot.observed_at)}</p>
          {sentence ? <p className="text-[13px]">{sentence}</p> : null}
          {snapshot.signals.length > 0 ? (
            <ul className="list-disc space-y-0.5 pl-4 text-[13px]">
              {snapshot.signals.slice(0, 3).map((signal) => (
                <li key={signal.code}>{signal.label}</li>
              ))}
            </ul>
          ) : null}
          {countText ? <p className="text-[13px] text-muted">{countText}</p> : null}
          <p className="text-[13px] text-muted">{snapshot.coverage.summary}</p>
          {snapshot.coverage.limitations.slice(0, 2).map((item) => (
            <p key={item.code} className="text-xs text-warning">
              {item.label}
            </p>
          ))}
          {stale ? (
            <Callout tone="warning" title="Snapshot is out of date">
              Refresh to read the resource again. Nothing is checked in the background.
            </Callout>
          ) : null}
          <Disclosure summary={<span className="text-[13px]">Pod and container state</span>}>
            {snapshot.pods.length === 0 ? (
              <p className="text-[13px] text-muted">No pods were inspected for this resource.</p>
            ) : (
              <ul className="space-y-2">
                {snapshot.pods.map((pod) => (
                  <li key={pod.name} className="text-[13px]">
                    <span className="font-medium">{pod.name}</span>
                    <span className="text-muted"> · {CATEGORY_LABEL[pod.category]}</span>
                    <ul className="mt-1 space-y-0.5 text-muted">
                      {pod.containers.map((item) => (
                        <li key={item.name}>
                          {item.name}
                          {item.state ? `, ${item.state}` : ", no observed state"}
                          {item.ready === true ? ", ready" : item.ready === false ? ", not ready" : ""}
                          {item.restart_count ? `, ${item.restart_count} restarts` : ""}
                          {item.waiting_reason ? `, waiting ${item.waiting_reason}` : ""}
                          {item.last_termination_reason ? `, last termination ${item.last_termination_reason}` : ""}
                          {item.last_exit_code !== null ? `, exit ${item.last_exit_code}` : ""}
                          {item.configured_memory_limit
                            ? `, configured memory limit ${item.configured_memory_limit}`
                            : ""}
                        </li>
                      ))}
                    </ul>
                  </li>
                ))}
              </ul>
            )}
          </Disclosure>
        </div>
      ) : null}

      {confirming ? (
        <Callout
          tone="info"
          title={`Investigate ${kind} ${name}?`}
          action={
            <span className="flex gap-2">
              <Button type="button" size="sm" variant="primary" onClick={onInvestigate}>
                Start investigation
              </Button>
              <Button type="button" size="sm" variant="ghost" onClick={() => setConfirming(false)}>
                Cancel
              </Button>
            </span>
          }
        >
          This starts the existing read-only investigation for the selected resource. It does not change the cluster.
        </Callout>
      ) : null}
    </section>
  );
}
