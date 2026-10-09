import { Link, useLocation } from "@tanstack/react-router";
import {
  Shield, Command, Search, Microscope, Activity,
  Settings, ChevronRight, Wifi, WifiOff, Cpu,
  AlertTriangle, CheckCircle2, Bell, LogOut, Wrench,
} from "lucide-react";
import { useEffect, useState, useRef, type ReactNode } from "react";

// ─────────────────────────────────────────────────────────────────────────────
// Navigation structure — 4 primary spaces
// ─────────────────────────────────────────────────────────────────────────────
export const NAV_SECTIONS = [
  {
    id: "command",
    label: "Command Center",
    icon: Command,
    to: "/",
    description: "Your security reality, right now",
  },
  {
    id: "investigations",
    label: "Investigations",
    icon: Microscope,
    to: "/investigations",
    description: "Active and resolved incidents",
  },
  {
    id: "activity",
    label: "Activity",
    icon: Activity,
    to: "/activity",
    description: "Processes, files, network, auth",
  },
  {
    id: "system",
    label: "System",
    icon: Settings,
    to: "/system",
    description: "Detection, response, devices, YARA",
  },
] as const;

// Legacy NAV export (kept for backward compatibility — some route files import it)
export const NAV = [
  { to: "/",             label: "Command Center",  icon: Command,    group: "Primary" },
  { to: "/investigations", label: "Investigations", icon: Microscope, group: "Primary" },
  { to: "/activity",     label: "Activity",         icon: Activity,   group: "Primary" },
  { to: "/system",       label: "System",           icon: Settings,   group: "Primary" },
] as const;

// ─────────────────────────────────────────────────────────────────────────────
// Security Posture Indicator
// ─────────────────────────────────────────────────────────────────────────────
function SecurityPosture({ score }: { score: number }) {
  const color =
    score >= 80 ? "var(--success)"
    : score >= 55 ? "var(--warning)"
    : "var(--critical)";
  const label =
    score >= 80 ? "PROTECTED"
    : score >= 55 ? "DEGRADED"
    : "AT RISK";
  return (
    <div className="flex items-center gap-2">
      <div
        className="dot-pulse size-2 rounded-full"
        style={{ background: color, color }}
      />
      <span
        className="font-mono text-[0.6rem] font-semibold tracking-widest"
        style={{ color }}
      >
        {label}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Sidebar nav item
// ─────────────────────────────────────────────────────────────────────────────
function NavItem({
  section,
  isActive,
}: {
  section: (typeof NAV_SECTIONS)[number];
  isActive: boolean;
}) {
  const Icon = section.icon;
  return (
    <Link
      to={section.to}
      activeOptions={{ exact: section.to === "/" }}
      className={`group flex items-center gap-3 rounded-xl border px-3 py-3 transition-all ${
        isActive
          ? "border-primary/30 bg-primary/10 text-primary"
          : "border-transparent text-muted-foreground hover:border-[var(--hairline)] hover:bg-white/3 hover:text-foreground"
      }`}
    >
      <div
        className={`flex size-8 shrink-0 items-center justify-center rounded-lg transition-all ${
          isActive ? "bg-primary/20" : "bg-white/4 group-hover:bg-white/8"
        }`}
      >
        <Icon className="size-4" />
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-medium leading-tight">{section.label}</p>
        <p className="mt-0.5 truncate text-[0.62rem] text-muted-foreground leading-tight">
          {section.description}
        </p>
      </div>
      {isActive && <ChevronRight className="size-3.5 shrink-0 text-primary" />}
    </Link>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// AppShell
// ─────────────────────────────────────────────────────────────────────────────
export function AppShell({
  children,
  backendOnline = false,
  wsConnected = false,
  onOpenWizard,
  onLogout,
}: {
  children: ReactNode;
  backendOnline?: boolean;
  wsConnected?: boolean;
  onOpenWizard?: () => void;
  onLogout?: () => void;
}) {
  const location = useLocation();
  const [postureScore, setPostureScore] = useState<number>(88);
  const [threatCount, setThreatCount] = useState<number>(0);
  const [eventsToday, setEventsToday] = useState<number>(0);
  const [mobileSidebarOpen, setMobileSidebarOpen] = useState(false);
  const scoreInterval = useRef<ReturnType<typeof setInterval> | null>(null);

  // Poll for live status
  useEffect(() => {
    const BASE =
      (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ??
      "http://localhost:8000";
    const token = localStorage.getItem("aiss_token") ?? "";

    const poll = async () => {
      try {
        const [statsRes, healthRes] = await Promise.allSettled([
          fetch(`${BASE}/api/threats/stats`, {
            headers: { Authorization: `Bearer ${token}` },
          }),
          fetch(`${BASE}/api/system/health`, {
            headers: { Authorization: `Bearer ${token}` },
          }),
        ]);

        if (statsRes.status === "fulfilled" && statsRes.value.ok) {
          const d = (await statsRes.value.json()) as {
            active?: number;
            total?: number;
          };
          const active = d.active ?? 0;
          setThreatCount(active);
          setEventsToday(d.total ?? 0);
          // Compute posture score: baseline 95, deduct for active threats
          const deduct = Math.min(active * 4, 60);
          setPostureScore(Math.max(95 - deduct, 20));
        }
      } catch {
        /* offline */
      }
    };

    void poll();
    scoreInterval.current = setInterval(() => void poll(), 15_000);
    return () => {
      if (scoreInterval.current) clearInterval(scoreInterval.current);
    };
  }, []);

  const activeSection = NAV_SECTIONS.find((s) =>
    s.to === "/" ? location.pathname === "/" : location.pathname.startsWith(s.to)
  );

  const statusColor = backendOnline ? "var(--success)" : "var(--critical)";

  return (
    <div className="flex min-h-screen w-full bg-[#070d0b]">
      {/* ── Desktop Sidebar ──────────────────────────────────────────────── */}
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-[var(--hairline)] bg-[var(--surface)] lg:flex">
        {/* Logo + status */}
        <div className="flex items-center justify-between border-b border-[var(--hairline)] px-4 py-4">
          <div className="flex items-center gap-2.5">
            <div className="flex size-8 items-center justify-center rounded-lg bg-primary/15 border border-primary/20">
              <Shield className="size-4 text-primary" />
            </div>
            <div>
              <p className="font-serif text-base font-bold leading-tight">AISS</p>
              <p className="label-cap text-[0.55rem]">Security System</p>
            </div>
          </div>
          <SecurityPosture score={postureScore} />
        </div>

        {/* Posture score bar */}
        <div className="border-b border-[var(--hairline)] px-4 py-3">
          <div className="flex items-center justify-between mb-1.5">
            <span className="label-cap text-[0.6rem]">Security Posture</span>
            <span
              className="font-mono text-sm font-bold"
              style={{
                color:
                  postureScore >= 80
                    ? "var(--success)"
                    : postureScore >= 55
                    ? "var(--warning)"
                    : "var(--critical)",
              }}
            >
              {postureScore}
              <span className="text-[0.6rem] text-muted-foreground"> / 100</span>
            </span>
          </div>
          <div className="h-1 w-full overflow-hidden rounded-full bg-white/8">
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${postureScore}%`,
                background:
                  postureScore >= 80
                    ? "var(--success)"
                    : postureScore >= 55
                    ? "var(--warning)"
                    : "var(--critical)",
              }}
            />
          </div>
          {threatCount > 0 && (
            <p className="mt-1.5 text-[0.6rem] text-[var(--warning)]">
              {threatCount} active threat{threatCount !== 1 ? "s" : ""} detected
            </p>
          )}
          {threatCount === 0 && (
            <p className="mt-1.5 text-[0.6rem] text-muted-foreground">
              {eventsToday.toLocaleString()} events analyzed today
            </p>
          )}
        </div>

        {/* Primary navigation */}
        <nav className="flex-1 overflow-y-auto p-3 space-y-1.5">
          {NAV_SECTIONS.map((section) => (
            <NavItem
              key={section.id}
              section={section}
              isActive={
                section.to === "/"
                  ? location.pathname === "/"
                  : location.pathname.startsWith(section.to)
              }
            />
          ))}
        </nav>

        {/* Footer status */}
        <div className="space-y-2 border-t border-[var(--hairline)] px-4 py-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <span
                className="size-1.5 rounded-full"
                style={{ background: statusColor }}
              />
              <span
                className="font-mono text-[0.58rem] tracking-widest uppercase"
                style={{ color: statusColor }}
              >
                {backendOnline ? "System Online" : "Backend Offline"}
              </span>
            </div>
            <div className="flex items-center gap-1">
              {wsConnected ? (
                <Wifi className="size-3 text-[var(--success)]" />
              ) : (
                <WifiOff className="size-3 text-[var(--warning)]" />
              )}
              <span className="font-mono text-[0.55rem] text-muted-foreground">
                {wsConnected ? "live" : "reconnecting"}
              </span>
            </div>
          </div>

          {!backendOnline && (
            <div className="rounded-lg border border-[var(--critical)]/25 bg-[var(--critical)]/8 px-3 py-2">
              <p className="font-mono text-[0.58rem] text-[var(--critical)] font-semibold mb-1">
                Backend offline
              </p>
              <p className="text-[0.58rem] text-muted-foreground leading-relaxed">
                Run{" "}
                <code className="font-mono text-foreground">python main.py</code>{" "}
                in the backend folder
              </p>
            </div>
          )}

          <div className="flex gap-1.5">
            {onOpenWizard && (
              <button
                onClick={onOpenWizard}
                className="flex flex-1 items-center justify-center gap-1.5 rounded-lg border border-[var(--hairline)] bg-white/3 px-2 py-1.5 text-[0.58rem] font-mono text-muted-foreground uppercase tracking-wide transition-colors hover:border-primary/40 hover:text-primary"
              >
                <Wrench className="size-3" /> Configure
              </button>
            )}
            {onLogout && (
              <button
                onClick={onLogout}
                className="flex items-center justify-center gap-1.5 rounded-lg border border-[var(--hairline)] bg-white/3 px-2 py-1.5 text-[0.58rem] font-mono text-muted-foreground uppercase tracking-wide transition-colors hover:border-[var(--critical)]/40 hover:text-[var(--critical)]"
              >
                <LogOut className="size-3" />
                <span className="sr-only lg:not-sr-only">Logout</span>
              </button>
            )}
          </div>

          <p className="font-mono text-[0.52rem] text-muted-foreground text-center">
            AISS v2.0.0
          </p>
        </div>
      </aside>

      {/* ── Mobile Sidebar overlay ─────────────────────────────────────── */}
      {mobileSidebarOpen && (
        <div className="fixed inset-0 z-50 lg:hidden">
          <div
            className="absolute inset-0 bg-black/60 backdrop-blur-sm"
            onClick={() => setMobileSidebarOpen(false)}
          />
          <aside className="absolute left-0 top-0 h-full w-72 flex flex-col border-r border-[var(--hairline)] bg-[var(--surface)]">
            <div className="flex items-center justify-between border-b border-[var(--hairline)] px-4 py-4">
              <div className="flex items-center gap-2.5">
                <Shield className="size-5 text-primary" />
                <p className="font-serif text-base font-bold">AISS</p>
              </div>
              <SecurityPosture score={postureScore} />
            </div>
            <nav className="flex-1 overflow-y-auto p-3 space-y-1.5">
              {NAV_SECTIONS.map((section) => (
                <div key={section.id} onClick={() => setMobileSidebarOpen(false)}>
                  <NavItem
                    section={section}
                    isActive={
                      section.to === "/"
                        ? location.pathname === "/"
                        : location.pathname.startsWith(section.to)
                    }
                  />
                </div>
              ))}
            </nav>
          </aside>
        </div>
      )}

      {/* ── Main content area ──────────────────────────────────────────── */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Top header */}
        <header className="sticky top-0 z-20 grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-b border-[var(--hairline)] bg-[var(--surface)]/95 px-4 py-3 backdrop-blur md:px-6">
          <div className="flex min-w-0 items-center gap-3">
            {/* Mobile menu button */}
            <button
              onClick={() => setMobileSidebarOpen(true)}
              className="lg:hidden flex size-8 items-center justify-center rounded-lg border border-[var(--hairline)] bg-white/3 text-muted-foreground hover:text-foreground"
            >
              <Shield className="size-4" />
            </button>

            {/* Breadcrumb */}
            <div className="hidden lg:flex items-center gap-2 text-muted-foreground text-sm">
              <span className="font-mono text-[0.65rem] tracking-widest uppercase text-primary">
                AISS
              </span>
              {activeSection && (
                <>
                  <ChevronRight className="size-3.5" />
                  <span className="text-foreground font-medium">
                    {activeSection.label}
                  </span>
                </>
              )}
            </div>

            {/* Search bar */}
            <label className="hidden flex-1 max-w-md items-center gap-2 rounded-xl border border-[var(--hairline)] bg-white/3 px-3 py-1.5 xl:flex">
              <Search className="size-3.5 shrink-0 text-muted-foreground" />
              <input
                placeholder="Search threats, processes, IPs…"
                className="w-full min-w-0 bg-transparent text-xs outline-none placeholder:text-muted-foreground"
              />
              <kbd className="shrink-0 rounded border border-[var(--hairline)] px-1.5 font-mono text-[0.5rem] text-muted-foreground">
                ⌘K
              </kbd>
            </label>
          </div>

          {/* Right side */}
          <div className="flex shrink-0 items-center gap-2">
            {/* Active threat indicator */}
            {threatCount > 0 && (
              <div className="hidden md:flex items-center gap-1.5 rounded-lg border border-[var(--critical)]/30 bg-[var(--critical)]/8 px-2.5 py-1">
                <AlertTriangle className="size-3.5 text-[var(--critical)]" />
                <span className="font-mono text-[0.62rem] text-[var(--critical)]">
                  {threatCount} active
                </span>
              </div>
            )}
            {threatCount === 0 && backendOnline && (
              <div className="hidden md:flex items-center gap-1.5 rounded-lg border border-[var(--success)]/20 bg-[var(--success)]/8 px-2.5 py-1">
                <CheckCircle2 className="size-3.5 text-[var(--success)]" />
                <span className="font-mono text-[0.62rem] text-[var(--success)]">
                  Clear
                </span>
              </div>
            )}

            {/* Connection dot */}
            <div className="hidden items-center gap-1.5 rounded-lg border border-[var(--hairline)] bg-white/3 px-2 py-1 sm:flex">
              <Cpu className="size-3.5 text-[var(--success)]" />
              <span className="font-mono text-[0.62rem] text-muted-foreground">live</span>
            </div>

            {/* Bell */}
            <button className="relative grid size-8 shrink-0 place-items-center rounded-lg border border-[var(--hairline)] bg-white/3 text-muted-foreground transition-colors hover:text-foreground">
              <Bell className="size-4" />
              {threatCount > 0 && (
                <span className="absolute -right-1 -top-1 flex size-3.5 items-center justify-center rounded-full bg-[var(--critical)] text-[0.45rem] font-bold text-white">
                  {Math.min(threatCount, 9)}
                </span>
              )}
            </button>

            {/* Avatar */}
            <div className="grid size-8 shrink-0 place-items-center rounded-full border border-[var(--hairline)] bg-primary/15 font-mono text-[0.65rem] text-primary">
              SA
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="min-w-0 flex-1 p-3 md:p-5">{children}</main>

        {/* Footer */}
        <footer className="flex items-center justify-between border-t border-[var(--hairline)] bg-[var(--surface)] px-4 py-2 md:px-6">
          <p className="truncate font-mono text-[0.58rem] text-muted-foreground">
            AISS v2.0.0 · AI Security Platform ·{" "}
            {backendOnline ? "backend connected" : "backend offline"}
          </p>
          <p
            className="shrink-0 font-mono text-[0.58rem]"
            style={{ color: statusColor }}
          >
            {backendOnline ? "● ONLINE" : "● OFFLINE"}
          </p>
        </footer>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// PageHeader — reusable section header used by all pages
// ─────────────────────────────────────────────────────────────────────────────
export function PageHeader({
  title,
  subtitle,
  right,
}: {
  title: string;
  subtitle?: string;
  right?: ReactNode;
}) {
  return (
    <div className="mb-4 flex flex-col gap-3 border-b border-[var(--hairline)] pb-4 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        <h1 className="truncate font-serif text-2xl font-bold">{title}</h1>
        {subtitle && (
          <p className="mt-1 truncate text-sm text-muted-foreground">{subtitle}</p>
        )}
      </div>
      {right && <div className="shrink-0">{right}</div>}
    </div>
  );
}
