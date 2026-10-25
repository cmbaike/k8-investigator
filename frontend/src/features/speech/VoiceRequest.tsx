import { Mic } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { ApiError } from "@/api/client";
import { endpoints } from "@/api/endpoints";
import { SCOPE_MESSAGES } from "@/api/scopeMessages";
import { Button } from "@/components/ui/button";
import { Field, Textarea } from "@/components/ui/field";
import type { SpeechProposal, TargetKind } from "@/types/api";
import { microphoneMessage, recordingIsEmpty, voiceCapture } from "./record";

const CLARIFY = "This request needs clarification. Name one workload, or ask about the namespace as a whole.";
const WORKLOAD_NAME = /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/;

function acceptedName(name: string | null): name is string {
  return !!name && name.length <= 63 && WORKLOAD_NAME.test(name);
}

export interface AppliedSpeech {
  question: string;
  scope: "workload" | "namespace";
  name?: string;
  kind?: TargetKind;
}

function speechFailure(error: ApiError): string {
  switch (error.status) {
    case 413:
      return "The recording is too large. Keep it under 30 seconds.";
    case 415:
      return "That audio format is not supported.";
    case 400:
      return "The recording was empty or could not be read.";
    case 503:
      return "Speech transcription is unavailable. Type the request instead.";
    case 504:
      return "Transcription took too long. Try a shorter recording, or type the request.";
    default:
      return error.kind === "timeout"
        ? "Transcription took too long. Try a shorter recording, or type the request."
        : "The recording could not be transcribed. Type the request instead.";
  }
}

function proposalMessage(proposal: SpeechProposal, namespace: string): string {
  if (proposal.outcome === "namespace") {
    return `Proposed: the whole namespace ${namespace}. Confirm to fill the form.`;
  }

  if (proposal.outcome === "workload" && acceptedName(proposal.name)) {
    const identity = proposal.kind ? `${proposal.kind} ${proposal.name}` : `workload ${proposal.name}`;

    return `Proposed: ${identity} in ${namespace}. Confirm to fill the form.`;
  }

  const known = proposal.code ? SCOPE_MESSAGES[proposal.code] : undefined;

  return known ?? CLARIFY;
}

function canApply(proposal: SpeechProposal | null): proposal is SpeechProposal {
  if (!proposal) return false;

  if (proposal.outcome === "namespace") return true;

  return proposal.outcome === "workload" && acceptedName(proposal.name);
}

export function VoiceRequest({
  namespace,
  onApply,
}: {
  namespace: string;
  onApply: (speech: AppliedSpeech) => void;
}) {
  const [phase, setPhase] = useState<"idle" | "recording" | "processing">("idle");
  const [error, setError] = useState<string | null>(null);
  const [transcript, setTranscript] = useState("");
  const [reviewing, setReviewing] = useState(false);
  const [proposal, setProposal] = useState<SpeechProposal | null>(null);
  const [proposalFor, setProposalFor] = useState("");
  const [checking, setChecking] = useState(false);
  const abortRef = useRef<AbortController | null>(null);
  const proposalSeq = useRef(0);

  useEffect(
    () => () => {
      abortRef.current?.abort("leave");
    },
    [],
  );

  useEffect(() => {
    const text = transcript.trim();
    const request = ++proposalSeq.current;

    if (!text || !namespace) {
      setProposal(null);
      setProposalFor("");
      setChecking(false);
      return;
    }

    const controller = new AbortController();
    setChecking(true);
    void endpoints
      .proposeSpeech({ transcript: text, namespace }, controller.signal)
      .then((result) => {
        if (request !== proposalSeq.current) return;

        setProposal(result);
        setProposalFor(text);
        setChecking(false);
      })
      .catch(() => {
        if (request !== proposalSeq.current) return;

        setProposal(null);
        setProposalFor("");
        setChecking(false);
        setError("The request could not be checked. The form is unchanged.");
      });

    return () => controller.abort();
  }, [transcript, namespace]);

  async function start() {
    if (phase !== "idle") return;

    setError(null);
    setPhase("recording");
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      const blob = await voiceCapture.record(controller.signal);

      if (controller.signal.aborted && controller.signal.reason === "leave") return;

      if (recordingIsEmpty(blob)) {
        setError("The recording was empty. Try again, or type the request.");
        setPhase("idle");
        return;
      }

      setPhase("processing");
      const result = await endpoints.transcribe(blob);
      const text = result.transcript.trim();

      if (!text) {
        setError("No speech was recognized. Correct the fields yourself, or try again.");
        setPhase("idle");
        return;
      }

      setTranscript(text);
      setReviewing(true);
      setPhase("idle");
    } catch (caught) {
      if (controller.signal.aborted && controller.signal.reason === "leave") return;

      setError(caught instanceof ApiError ? speechFailure(caught) : microphoneMessage(caught));
      setPhase("idle");
    }
  }

  function stop() {
    abortRef.current?.abort("stop");
  }

  function apply() {
    const text = transcript.trim();

    if (!canApply(proposal) || proposalFor !== text) return;

    onApply(
      proposal.outcome === "namespace"
        ? { question: text, scope: "namespace" }
        : {
            question: text,
            scope: "workload",
            name: proposal.name ?? undefined,
            kind: proposal.kind ?? undefined,
          },
    );
  }

  const ready = canApply(proposal) && proposalFor === transcript.trim() && !checking;
  const review = proposal && proposalFor === transcript.trim() && !checking ? proposalMessage(proposal, namespace) : null;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        {phase === "recording" ? (
          <Button type="button" onClick={stop}>
            Stop recording
          </Button>
        ) : (
          <Button type="button" onClick={() => void start()} disabled={phase === "processing"}>
            <Mic aria-hidden="true" className="size-3.5" />
            {phase === "processing" ? "Transcribing…" : "Speak a request"}
          </Button>
        )}
        <p className="text-xs text-muted">Speech fills the form after you confirm. It does not start the investigation.</p>
      </div>
      {phase === "recording" ? (
        <p role="status" className="text-xs text-muted">
          Recording. Select Stop when you finish. Recording ends at 30 seconds.
        </p>
      ) : null}
      {checking ? (
        <p role="status" className="text-xs text-muted">
          Checking this request.
        </p>
      ) : null}
      {error ? (
        <p role="alert" className="text-xs text-critical">
          {error}
        </p>
      ) : null}
      {reviewing ? (
        <Field
          label="Recognized speech"
          htmlFor="recognized-speech"
          hint="Raw transcript. Edit a misheard word, then confirm. The proposal below is only the scope."
        >
          <Textarea
            id="recognized-speech"
            value={transcript}
            maxLength={3800}
            rows={2}
            className="min-h-14"
            onChange={(event) => {
              setError(null);
              setTranscript(event.target.value);
            }}
          />
        </Field>
      ) : null}
      {review ? (
        <p role="status" className="text-xs text-muted">
          {review}
        </p>
      ) : null}
      {reviewing ? (
        <Button type="button" onClick={apply} disabled={!ready}>
          Use this request
        </Button>
      ) : null}
    </div>
  );
}
