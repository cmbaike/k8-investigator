import { cva, type VariantProps } from "class-variance-authority";
import type { HTMLAttributes } from "react";
import { cn } from "@/lib";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-1.5 py-px text-[11px] font-medium leading-4 whitespace-nowrap",
  {
    variants: {
      tone: {
        neutral: "border-border bg-surface-2 text-muted",
        critical: "border-critical/25 bg-critical/10 text-critical",
        warning: "border-warning/25 bg-warning/10 text-warning",
        ok: "border-ok/25 bg-ok/10 text-ok",
        info: "border-info/25 bg-info/10 text-info",
        unverified: "border-unverified/30 bg-unverified/10 text-unverified",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone }), className)} {...props} />;
}
