import type { ReactNode } from "react";

export function PageHeader({ title, description, actions }: { title: string; description?: string; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-3">
      <div className="space-y-0.5">
        <h1 className="text-lg font-semibold tracking-tight">{title}</h1>
        {description ? <p className="text-[13px] text-muted">{description}</p> : null}
      </div>
      {actions}
    </div>
  );
}
