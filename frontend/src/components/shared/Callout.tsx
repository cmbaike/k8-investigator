import { AlertTriangle, Info, OctagonAlert } from "lucide-react";
import type { ReactNode } from "react";
import { cn } from "@/lib";

const tones = {
  info: { icon: Info, style: "border-border bg-surface-2/60", iconStyle: "text-info" },
  warning: { icon: AlertTriangle, style: "border-warning/25 bg-warning/8", iconStyle: "text-warning" },
  error: { icon: OctagonAlert, style: "border-critical/25 bg-critical/8", iconStyle: "text-critical" },
} as const;

export function Callout({
  tone = "info",
  title,
  children,
  action,
  className,
}: {
  tone?: keyof typeof tones;
  title?: string;
  children?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  const { icon: Icon, style, iconStyle } = tones[tone];

  return (
    <div
      role={tone === "error" ? "alert" : "status"}
      className={cn("flex items-start gap-3 rounded-lg border px-3.5 py-3", style, className)}
    >
      <Icon aria-hidden="true" className={cn("mt-0.5 size-4 shrink-0", iconStyle)} />
      <div className="min-w-0 flex-1 space-y-0.5">
        {title ? <p className="text-[13px] font-medium">{title}</p> : null}
        {children ? <div className="text-[13px] text-muted">{children}</div> : null}
      </div>
      {action}
    </div>
  );
}
