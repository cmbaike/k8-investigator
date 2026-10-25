import { ChevronRight } from "lucide-react";
import { useId, useState, type ReactNode } from "react";
import { cn } from "@/lib";

// A button-controlled disclosure. The summary stays visible; the panel is
// rendered only while open.
export function Disclosure({ summary, children, defaultOpen = false, className }: {
  summary: ReactNode;
  children: ReactNode;
  defaultOpen?: boolean;
  className?: string;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const panelId = useId();

  return (
    <div className={className}>
      <button
        type="button"
        aria-expanded={open}
        aria-controls={panelId}
        onClick={() => setOpen((value) => !value)}
        className="flex w-full cursor-pointer items-center gap-2 px-3 py-2 text-left transition-colors hover:bg-surface-2/60"
      >
        <ChevronRight aria-hidden="true" className={cn("size-3.5 shrink-0 text-muted transition-transform", open && "rotate-90")} />
        <span className="flex min-w-0 flex-1 items-center gap-2">{summary}</span>
      </button>
      {open ? (
        <div id={panelId} className="space-y-2 px-3 pt-1 pb-3 pl-8">
          {children}
        </div>
      ) : null}
    </div>
  );
}
