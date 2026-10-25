import { useEffect, useRef, useState } from "react";
import { endpoints, briefingAudioPath } from "@/api/endpoints";
import { Button } from "@/components/ui/button";
import { useSpokenResponses } from "./preference";

type Phase = "idle" | "loading" | "playing" | "paused" | "error";

export function SpokenSummary({ investigationId }: { investigationId: string }) {
  const { enabled, setEnabled } = useSpokenResponses();
  const audioRef = useRef<HTMLAudioElement | null>(null);
  const [phase, setPhase] = useState<Phase>("idle");
  const [text, setText] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hasAudio, setHasAudio] = useState(false);

  function stopPlayback() {
    const audio = audioRef.current;

    if (!audio) return;

    audio.pause();
    audio.currentTime = 0;
    setPhase("idle");
  }

  useEffect(
    () => () => {
      audioRef.current?.pause();
    },
    [],
  );

  async function loadText() {
    const briefing = await endpoints.briefing(investigationId);
    setText(briefing.text);

    return briefing;
  }

  function listen() {
    if (!enabled) return;

    setError(null);
    setPhase("loading");
    const audio = audioRef.current ?? new Audio();
    audioRef.current = audio;
    setHasAudio(true);
    audio.src = briefingAudioPath(investigationId);
    audio.onended = () => setPhase("idle");
    audio.onerror = () => {
      setPhase("error");
      setError("Spoken audio is unavailable. The briefing text is the exact summary.");
    };
    void audio.play().then(
      () => setPhase("playing"),
      () => {
        setPhase("error");
        setError("The browser blocked playback. Use Listen to summary to try again.");
      },
    );
    void loadText()
      .then((briefing) => {
        if (!briefing.speech_available) {
          audio.pause();
          setPhase("error");
          setError("Speech synthesis is unavailable. The briefing text above is the exact summary.");
        }
      })
      .catch(() => {
        setError("The spoken briefing could not be loaded. The written report is unchanged.");
      });
  }

  function pause() {
    audioRef.current?.pause();
    setPhase("paused");
  }

  function resume() {
    void audioRef.current?.play().then(
      () => setPhase("playing"),
      () => setPhase("error"),
    );
  }

  function replay() {
    const audio = audioRef.current;

    if (!audio || !enabled) return;

    audio.currentTime = 0;
    void audio.play().then(
      () => setPhase("playing"),
      () => setPhase("error"),
    );
  }

  function showText() {
    setError(null);
    void loadText().catch(() => {
      setError("The spoken briefing could not be loaded. The written report is unchanged.");
    });
  }

  return (
    <section aria-label="Spoken summary" className="flex flex-col gap-2 rounded-md border border-border bg-surface px-3 py-2">
      <div className="flex flex-wrap items-center gap-2">
        {enabled ? (
          <>
            <Button size="sm" onClick={listen} disabled={phase === "loading"}>
              Listen to summary
            </Button>
            <Button size="sm" variant="ghost" onClick={pause} disabled={phase !== "playing"}>
              Pause
            </Button>
            <Button size="sm" variant="ghost" onClick={resume} disabled={phase !== "paused"}>
              Resume
            </Button>
            <Button size="sm" variant="ghost" onClick={stopPlayback} disabled={phase !== "playing" && phase !== "paused"}>
              Stop
            </Button>
            <Button size="sm" variant="ghost" onClick={replay} disabled={!hasAudio}>
              Replay
            </Button>
          </>
        ) : (
          <Button size="sm" onClick={showText}>
            Show briefing text
          </Button>
        )}
        <label className="ml-auto flex items-center gap-1.5 text-xs text-muted">
          <input
            type="checkbox"
            checked={enabled}
            onChange={(event) => {
              const next = event.target.checked;
              setEnabled(next);

              if (!next) stopPlayback();
            }}
          />
          Spoken responses
        </label>
      </div>
      {error ? (
        <p role="alert" className="text-xs text-critical">
          {error}
        </p>
      ) : null}
      {text ? (
        <p className="text-[13px] leading-relaxed text-muted" aria-live="polite">
          {text}
        </p>
      ) : null}
    </section>
  );
}
