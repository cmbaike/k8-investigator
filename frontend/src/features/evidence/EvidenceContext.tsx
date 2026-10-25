import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from "react";
import type { EvidenceEntry } from "./evidenceIndex";

interface EvidenceContextValue {
  index: Map<string, EvidenceEntry>;
  openId: string | null;
  open: (id: string) => void;
  toggle: (id: string) => void;
}

const EvidenceContext = createContext<EvidenceContextValue | null>(null);

export function evidenceElementId(id: string): string {
  return `evidence-${id}`;
}

export function EvidenceProvider({ index, onReveal, children }: {
  index: Map<string, EvidenceEntry>;
  /** Called before a reference is opened, so its container can become visible. */
  onReveal?: () => void;
  children: ReactNode;
}) {
  const [openId, setOpenId] = useState<string | null>(null);

  const open = useCallback((id: string) => {
    onReveal?.();
    setOpenId(id);
    // Wait for the row to expand, then bring it into view.
    window.setTimeout(() => {
      document.getElementById(evidenceElementId(id))?.scrollIntoView({ block: "center", behavior: "smooth" });
    }, 0);
  }, [onReveal]);

  const toggle = useCallback((id: string) => setOpenId((current) => (current === id ? null : id)), []);
  const value = useMemo(() => ({ index, openId, open, toggle }), [index, openId, open, toggle]);

  return <EvidenceContext.Provider value={value}>{children}</EvidenceContext.Provider>;
}

export function useEvidence(): EvidenceContextValue {
  const value = useContext(EvidenceContext);

  if (!value) throw new Error("useEvidence must be used inside EvidenceProvider.");

  return value;
}
