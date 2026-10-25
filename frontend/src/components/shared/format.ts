import type { InvestigationStatus, Severity } from "@/types/api";

export function formatDuration(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return "—";
  if (seconds < 1) return "<1 s";
  if (seconds < 60) return `${seconds.toFixed(1)} s`;

  const minutes = Math.floor(seconds / 60);

  return `${minutes} min ${Math.round(seconds - minutes * 60)} s`;
}

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "medium" });

export function formatTimestamp(value: string | null | undefined): string {
  if (!value) return "—";

  const date = new Date(value);

  return Number.isNaN(date.getTime()) ? "—" : dateFormat.format(date);
}

const clockFormat = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false });
const compactFormat = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", hour12: false });

/** HH:MM:SS, for dense lists where the full timestamp is in the title. */
export function formatClock(value: string | null | undefined): string {
  if (!value) return "—";

  const date = new Date(value);

  return Number.isNaN(date.getTime()) ? "—" : clockFormat.format(date);
}

/** "Oct 18, 18:52". */
export function formatCompact(value: string | null | undefined): string {
  if (!value) return "—";

  const date = new Date(value);

  return Number.isNaN(date.getTime()) ? "—" : compactFormat.format(date);
}

export function shortId(id: string): string {
  return id.length > 8 ? id.slice(0, 8) : id;
}

export const STATUS_LABEL: Record<InvestigationStatus, string> = {
  pending: "Pending",
  running: "Running",
  completed: "Completed",
  failed: "Failed",
};

export const STATUS_TONE: Record<InvestigationStatus, "neutral" | "info" | "ok" | "critical"> = {
  pending: "neutral",
  running: "info",
  completed: "ok",
  failed: "critical",
};

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  warning: "Warning",
  info: "Info",
  unknown: "Unknown",
};

export const SEVERITY_TONE: Record<Severity, "critical" | "warning" | "info" | "neutral"> = {
  critical: "critical",
  warning: "warning",
  info: "info",
  unknown: "neutral",
};
