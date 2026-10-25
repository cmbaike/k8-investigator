import { History, LayoutDashboard, Moon, PlusCircle, ShieldCheck, Sun } from "lucide-react";
import { NavLink, Outlet } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { useAccess } from "@/features/auth/AuthProvider";
import { useHealth } from "@/hooks/useHealth";
import { useTheme } from "@/hooks/useTheme";
import { cn } from "@/lib";

const links = [
  { to: "/", label: "Overview", icon: LayoutDashboard, end: true },
  { to: "/investigations/new", label: "New investigation", icon: PlusCircle, end: true },
  { to: "/investigations", label: "History", icon: History, end: true },
] as const;

function HealthIndicator() {
  const { data, isError, isPending } = useHealth();
  const tone = isPending ? "bg-muted" : isError ? "bg-critical" : data?.status === "ok" ? "bg-ok" : "bg-warning";
  const label = isPending
    ? "Checking API…"
    : isError
      ? "API unreachable"
      : data?.status === "ok"
        ? "API and database reachable"
        : "API up, database unreachable";

  return (
    <div className="flex items-center gap-2 text-xs text-muted" role="status">
      <span aria-hidden="true" className={cn("size-2 rounded-full", tone)} />
      {label}
    </div>
  );
}

export function AppShell() {
  const { access } = useAccess();
  const { theme, toggle } = useTheme();
  const namespaces = access?.allowed_namespaces.join(", ");

  return (
    <div className="flex h-full">
      <aside className="hidden w-52 shrink-0 flex-col border-r border-border bg-surface md:flex">
        <div className="flex h-12 items-center gap-2 px-4 text-[13px] font-semibold">
          <ShieldCheck aria-hidden="true" className="size-4 text-accent" />
          Private AI SRE
        </div>
        <nav aria-label="Primary" className="flex-1 space-y-0.5 px-2 py-2">
          {links.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2 rounded-md px-2.5 py-1.5 text-[13px] transition-colors",
                  isActive ? "bg-surface-2 font-medium text-foreground" : "text-muted hover:bg-surface-2 hover:text-foreground",
                )
              }
            >
              <Icon aria-hidden="true" className="size-4" />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="space-y-1 border-t border-border px-4 py-3">
          <HealthIndicator />
          <p className="text-xs text-muted">Read-only. Never changes the cluster.</p>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center justify-between gap-3 border-b border-border px-4">
          <nav aria-label="Mobile" className="flex min-w-0 gap-0.5 overflow-x-auto md:hidden">
            {links.map(({ to, label, end }) => (
              <NavLink
                key={to}
                to={to}
                end={end}
                className={({ isActive }) =>
                  cn("whitespace-nowrap rounded-md px-2 py-1 text-xs", isActive ? "bg-surface-2 font-medium" : "text-muted")
                }
              >
                {label}
              </NavLink>
            ))}
          </nav>
          <div className="hidden text-xs text-muted md:block">
            Namespaces:{" "}
            <span className="font-mono text-foreground">{namespaces || "loading…"}</span>
          </div>
          <div className="flex items-center gap-1">
            <Button
              variant="ghost"
              size="sm"
              onClick={toggle}
              aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}
            >
              {theme === "dark" ? <Sun aria-hidden="true" className="size-4" /> : <Moon aria-hidden="true" className="size-4" />}
            </Button>
          </div>
        </header>
        <main className="min-h-0 flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-5xl space-y-5 px-4 py-6 sm:px-6">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
