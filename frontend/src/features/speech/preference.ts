import { useCallback, useEffect, useState } from "react";

// A display preference, like the theme. Never a credential.
const KEY = "pai-spoken";

export function spokenResponsesEnabled(): boolean {
  try {
    return window.localStorage.getItem(KEY) !== "off";
  } catch {
    return true;
  }
}

export function setSpokenResponsesEnabled(enabled: boolean): void {
  try {
    window.localStorage.setItem(KEY, enabled ? "on" : "off");
  } catch {
    // Preference simply is not persisted.
  }
}

export function useSpokenResponses(): { enabled: boolean; setEnabled: (enabled: boolean) => void } {
  const [enabled, setEnabledState] = useState(spokenResponsesEnabled);
  const setEnabled = useCallback((next: boolean) => {
    setSpokenResponsesEnabled(next);
    setEnabledState(next);
  }, []);

  useEffect(() => {
    setEnabledState(spokenResponsesEnabled());
  }, []);

  return { enabled, setEnabled };
}
