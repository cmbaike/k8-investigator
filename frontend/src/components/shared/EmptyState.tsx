import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export function EmptyState({ icon: Icon, title, hint, action }: {
  icon: LucideIcon;
  title: string;
  hint?: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-2 px-6 py-10 text-center">
      <Icon aria-hidden="true" className="size-5 text-muted" />
      <p className="text-sm font-medium">{title}</p>
      {hint ? <p className="max-w-sm text-[13px] text-muted">{hint}</p> : null}
      {action}
    </div>
  );
}
