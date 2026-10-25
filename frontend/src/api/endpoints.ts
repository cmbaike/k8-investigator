import { api, EXECUTE_TIMEOUT_MS } from "./client";
import type {
  AuditTrail,
  CreateInvestigationRequest,
  HealthInfo,
  InvestigationPage,
  InvestigationRecord,
  InvestigationReport,
  InvestigationStats,
  InvestigationStatus,
  InvestigationSummary,
  ResourceHealth,
  AccessInfo,
  SpeechProposal,
  SpokenBriefing,
} from "@/types/api";

export const endpoints = {
  access: () => api<AccessInfo>("/access"),
  health: () => api<HealthInfo>("/health"),
  stats: () => api<InvestigationStats>("/investigations/stats"),
  list: (params: { limit: number; offset: number; status?: InvestigationStatus }) => {
    const query = new URLSearchParams({ limit: String(params.limit), offset: String(params.offset) });
    if (params.status) query.set("status", params.status);
    return api<InvestigationPage>(`/investigations?${query}`);
  },
  summary: (id: string) => api<InvestigationSummary>(`/investigations/${encodeURIComponent(id)}/summary`),
  report: (id: string) => api<InvestigationReport>(`/investigations/${encodeURIComponent(id)}/report`),
  audit: (id: string) => api<AuditTrail>(`/investigations/${encodeURIComponent(id)}/audit`),
  // Create and execute are SEPARATE requests; neither is ever retried
  // automatically (a lost response must not create or execute twice).
  create: (body: CreateInvestigationRequest) =>
    api<InvestigationRecord>("/investigations", { method: "POST", body }),
  execute: (id: string) =>
    api<InvestigationRecord>(`/investigations/${encodeURIComponent(id)}/execute`, {
      method: "POST",
      timeoutMs: EXECUTE_TIMEOUT_MS,
    }),
  transcribe: (audio: Blob) => {
    const form = new FormData();
    form.append("audio", audio, "request.wav");

    return api<{ transcript: string }>("/speech/transcribe", { method: "POST", form, timeoutMs: 60_000 });
  },
  proposeSpeech: (body: { transcript: string; namespace: string }, signal?: AbortSignal) =>
    api<SpeechProposal>("/speech/proposal", { method: "POST", body, signal }),
  briefing: (id: string) => api<SpokenBriefing>(`/investigations/${encodeURIComponent(id)}/briefing`),
  resourceHealth: (
    query: { namespace: string; kind: string; name: string },
    signal?: AbortSignal,
  ) => {
    const params = new URLSearchParams(query);
    return api<ResourceHealth>(`/resources/health?${params}`, { signal, timeoutMs: 20_000 });
  },
};

export function briefingAudioPath(id: string): string {
  return `/api/investigations/${encodeURIComponent(id)}/briefing/audio`;
}
