import { useId, useRef, type KeyboardEvent, type ReactNode } from "react";
import { cn } from "@/lib";

export interface TabItem {
  id: string;
  label: string;
  /** A short count shown beside the label. */
  count?: number | string | null;
  /** Draws attention to a tab whose content is a caveat. */
  attention?: boolean;
  panel: ReactNode;
}

// WAI-ARIA tabs with automatic activation: arrow keys, Home and End move
// between tabs. Only the active panel is rendered.
export function Tabs({ label, items, value, onChange }: {
  label: string;
  items: TabItem[];
  value: string;
  onChange: (id: string) => void;
}) {
  const base = useId();
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const active = items.find((item) => item.id === value) ?? items[0];

  function onKeyDown(event: KeyboardEvent, position: number) {
    const last = items.length - 1;
    const target =
      event.key === "ArrowRight" ? (position === last ? 0 : position + 1)
      : event.key === "ArrowLeft" ? (position === 0 ? last : position - 1)
      : event.key === "Home" ? 0
      : event.key === "End" ? last
      : null;

    if (target === null) return;

    event.preventDefault();
    const next = items[target];

    if (!next) return;

    onChange(next.id);
    refs.current[next.id]?.focus();
  }

  if (!active) return null;

  return (
    <div className="rounded-lg border border-border bg-surface">
      <div role="tablist" aria-label={label} className="flex gap-1 overflow-x-auto overflow-y-hidden border-b border-border px-2">
        {items.map((item, position) => {
          const selected = item.id === active.id;

          return (
            <button
              key={item.id}
              ref={(node) => {
                refs.current[item.id] = node;
              }}
              type="button"
              role="tab"
              id={`${base}-tab-${item.id}`}
              aria-selected={selected}
              aria-controls={`${base}-panel-${item.id}`}
              tabIndex={selected ? 0 : -1}
              onClick={() => onChange(item.id)}
              onKeyDown={(event) => onKeyDown(event, position)}
              className={cn(
                "relative flex cursor-pointer items-center gap-1.5 whitespace-nowrap px-2.5 py-2.5 text-[13px] font-medium transition-colors",
                selected ? "text-foreground" : "text-muted hover:text-foreground",
              )}
            >
              {item.label}
              {item.count !== undefined && item.count !== null ? " " : null}
              {item.count !== undefined && item.count !== null ? (
                <span
                  className={cn(
                    "rounded px-1 text-[11px] tabular-nums",
                    item.attention ? "bg-warning/15 text-warning" : "bg-surface-2 text-muted",
                  )}
                >
                  {item.count}
                </span>
              ) : null}
              {selected ? <span aria-hidden="true" className="absolute inset-x-2 bottom-0 h-px bg-foreground" /> : null}
            </button>
          );
        })}
      </div>
      <div role="tabpanel" id={`${base}-panel-${active.id}`} aria-labelledby={`${base}-tab-${active.id}`} tabIndex={0} className="p-4">
        {active.panel}
      </div>
    </div>
  );
}
