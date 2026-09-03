import { Link } from "@tanstack/react-router";
import {
  LayoutDashboard, ShieldAlert, Siren, Server, Network, BarChart3,
  Users, Settings, Shield, Search, Bell, Activity,
  Radar, Radio, Globe2, Bug, ScanLine,
  History, Workflow, Bot, Target, PlayCircle, MessageSquare,
} from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";

export const NAV = [
  // Monitor
  { to: "/ai-console",          label: "AI Console",           icon: MessageSquare,   group: "Monitor" },
  { to: "/",                    label: "Security Overview",    icon: LayoutDashboard, group: "Monitor" },
  { to: "/threats",             label: "Threat Detection",     icon: ShieldAlert,     group: "Monitor" },
  { to: "/incidents",           label: "Incidents",            icon: Siren,           group: "Monitor" },
  { to: "/live-monitoring",     label: "Live Monitoring",      icon: Radio,           group: "Monitor" },
  // Network Security
  { to: "/network-monitor",     label: "Network Monitor",      icon: Network,         group: "Network Security" },
  { to: "/network",             label: "Network Discovery",    icon: Radar,           group: "Network Security" },
  { to: "/security-gateway",    label: "Security Gateway",     icon: Shield,          group: "Network Security" },
  // Threat Intelligence
  { to: "/threat-intelligence", label: "IOC & Intel Feeds",    icon: Globe2,          group: "Intelligence" },
  { to: "/malware-analysis",    label: "File / Malware Analysis", icon: Bug,          group: "Intelligence" },
  // MITRE ATT&CK is rendered as a plain <a> tag in nav (dynamic route)
  // Vulnerability & Assets
  { to: "/vulnerability-scanner", label: "Vulnerability Scanner", icon: ScanLine,    group: "Vulnerability" },
  { to: "/assets",              label: "Assets",               icon: Server,          group: "Vulnerability" },
  // AI & Automation
  { to: "/agent",               label: "AI Security Agent",    icon: Bot,             group: "AI & Automation" },
  { to: "/playbooks",           label: "Playbooks",            icon: Workflow,        group: "AI & Automation" },
  { to: "/jobs",                label: "Scan Jobs",            icon: PlayCircle,      group: "AI & Automation" },
  // Reports & Audit
  { to: "/reports",             label: "Reports",              icon: BarChart3,       group: "Reporting" },
  { to: "/audit-logs",          label: "Audit Logs",           icon: History,         group: "Reporting" },
  // Settings
  { to: "/system-health",       label: "System Health",        icon: Activity,        group: "Settings" },
  { to: "/users",               label: "Users & Access",       icon: Users,           group: "Settings" },
  { to: "/settings",            label: "Settings",             icon: Settings,        group: "Settings" },
] as const;

const GROUPS = ["Monitor", "Network Security", "Intelligence", "Vulnerability", "AI & Automation", "Reporting", "Settings"] as const;

function Clock() {
  const [now, setNow] = useState<Date | null>(null);
  useEffect(() => {
    setNow(new Date());
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <div className="hidden text-right sm:block">
      <p className="font-mono text-sm text-foreground">{now ? now.toTimeString().slice(0, 8) : "--:--:--"}</p>
      <p className="label-cap">{now ? now.toDateString() : "SYNCING"}</p>
    </div>
  );
}

export function AppShell({
  children,
  backendOnline = false,
  wsConnected   = false,
  onOpenWizard,
  onLogout,
}: {
  children:       ReactNode;
  backendOnline?: boolean;
  wsConnected?:   boolean;
  onOpenWizard?:  () => void;
  onLogout?:      () => void;
}) {
  const [sensorCount, setSensorCount] = useState<number | null>(null);

  useEffect(() => {
    const poll = async () => {
      try {
        const r = await fetch(
          ((import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000") + "/api/system/health",
          { headers: { Authorization: `Bearer ${localStorage.getItem("aiss_token") ?? ""}` } }
        );
        if (r.ok) {
          const d = await r.json() as { process_count?: number };
          setSensorCount(d.process_count ?? null);
        }
      } catch { /* offline */ }
    };
    void poll();
    const t = setInterval(() => void poll(), 8000);
    return () => clearInterval(t);
  }, []);

  const statusColor = backendOnline ? "var(--success)" : "var(--critical)";
  const statusText  = backendOnline ? "SYSTEM ONLINE"  : "BACKEND OFFLINE";

  return (
    <div className="flex min-h-screen w-full bg-[#070d0b]">
      <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-[var(--hairline)] bg-[var(--surface)] lg:flex">
        <div className="flex items-center gap-2.5 border-b border-[var(--hairline)] px-5 py-4">
          <Shield className="size-5 shrink-0 text-primary" />
          <div className="min-w-0">
            <p className="font-serif text-base leading-none font-bold">AISS</p>
            <p className="label-cap mt-1 truncate text-[0.6rem]">Security System</p>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto p-3">
          {GROUPS.map((g) => (
            <div key={g} className="mb-3">
              <p className="label-cap mb-1.5 px-3 text-[0.55rem]">{g}</p>
              <div className="space-y-0.5">
                {NAV.filter((n) => n.group === g).map((item) => (
                  <Link
                    key={item.to}
                    to={item.to}
                    activeOptions={{ exact: item.to === "/" }}
                    activeProps={{ className: "bg-primary/12 text-primary border-primary/30" }}
                    inactiveProps={{ className: "text-muted-foreground border-transparent" }}
                    className="flex items-center gap-2.5 rounded-md border px-3 py-2 text-sm transition-colors hover:bg-white/4 hover:text-foreground"
                  >
                    <item.icon className="size-4 shrink-0" />
                    <span className="truncate">{item.label}</span>
                  </Link>
                ))}
                {g === "Intelligence" && (
                  <a
                    href="/mitre/t1566.001"
                    className="flex items-center gap-2.5 rounded-md border border-transparent px-3 py-2 text-sm text-muted-foreground transition-colors hover:bg-white/4 hover:text-foreground"
                  >
                    <Target className="size-4 shrink-0" />
                    <span className="truncate">MITRE ATT&amp;CK</span>
                  </a>
                )}
              </div>
            </div>
          ))}
        </nav>
        <div className="space-y-2 border-t border-[var(--hairline)] px-4 py-3">
          <div className="grid grid-cols-2 gap-2">
            <div className="rounded-md border border-[var(--hairline)] bg-white/3 px-2 py-1.5">
              <p className="label-cap text-[0.5rem]">Processes</p>
              <p className="font-mono text-sm">{sensorCount ?? "â€”"}</p>
            </div>
            <div className="rounded-md border border-[var(--hairline)] bg-white/3 px-2 py-1.5">
              <p className="label-cap text-[0.5rem]">Backend</p>
              <p className="font-mono text-xs" style={{ color: statusColor }}>{backendOnline ? "online" : "offline"}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="dot-pulse size-1.5 rounded-full" style={{ background: statusColor, color: statusColor }} />
            <span className="font-mono text-[0.62rem] tracking-[0.14em]" style={{ color: statusColor }}>{statusText}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="size-1.5 rounded-full" style={{ background: wsConnected ? "var(--success)" : "var(--warning)" }} />
            <span className="font-mono text-[0.6rem] text-muted-foreground">WS {wsConnected ? "live" : "disconnected"}</span>
          </div>
          {onOpenWizard && (
            <button type="button" onClick={onOpenWizard}
              className="w-full rounded-md border border-[var(--hairline)] bg-white/3 px-2 py-1.5 text-left font-mono text-[0.58rem] text-muted-foreground tracking-[0.08em] uppercase transition-colors hover:border-primary/40 hover:text-primary">
              âš™ Configure AISS
            </button>
          )}
          {!backendOnline && (
            <div className="rounded-md border border-[var(--critical)]/30 bg-[var(--critical)]/8 px-2 py-1.5">
              <p className="font-mono text-[0.58rem] text-[var(--critical)] font-semibold mb-0.5">Backend offline</p>
              <p className="text-[0.58rem] text-muted-foreground leading-relaxed">
                Run: <span className="font-mono text-foreground">python main.py</span> in the backend folder to start AISS
              </p>
            </div>
          )}
          {onLogout && (
            <button type="button" onClick={onLogout}
              className="w-full rounded-md border border-[var(--hairline)] bg-white/3 px-2 py-1.5 text-left font-mono text-[0.58rem] text-muted-foreground tracking-[0.08em] uppercase transition-colors hover:border-[var(--critical)]/40 hover:text-[var(--critical)]">
              â» Logout
            </button>
          )}
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-20 grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-b border-[var(--hairline)] bg-[var(--surface)]/95 px-4 py-3 backdrop-blur md:px-6">
          <div className="flex min-w-0 items-center gap-3">
            <Shield className="size-5 shrink-0 text-primary lg:hidden" />
            <div className="min-w-0">
              <p className="truncate font-serif text-sm font-bold">Artificial Intelligence Security System</p>
              <p className="label-cap truncate">Security Operations Center</p>
            </div>
            <label className="ml-2 hidden min-w-0 flex-1 items-center gap-2 rounded-md border border-[var(--hairline)] bg-white/3 px-3 py-1.5 xl:flex">
              <Search className="size-3.5 shrink-0 text-muted-foreground" />
              <input placeholder="Search assets, IPs, incidentsâ€¦" className="w-full min-w-0 bg-transparent text-xs outline-none placeholder:text-muted-foreground" />
              <kbd className="shrink-0 rounded border border-[var(--hairline)] px-1 font-mono text-[0.55rem] text-muted-foreground">âŒ˜K</kbd>
            </label>
          </div>
          <div className="flex items-center gap-3">
            <span className="hidden items-center gap-1.5 rounded-md border border-[var(--hairline)] bg-white/3 px-2 py-1 md:flex">
              <Activity className="size-3.5 text-[var(--success)]" />
              <span className="font-mono text-[0.62rem] text-muted-foreground">live</span>
            </span>
            <button className="relative grid size-8 shrink-0 place-items-center rounded-md border border-[var(--hairline)] bg-white/3 text-muted-foreground transition-colors hover:text-foreground">
              <Bell className="size-4" />
            </button>
            <Clock />
            <div className="grid size-8 shrink-0 place-items-center rounded-full border border-[var(--hairline)] bg-white/4 font-mono text-[0.65rem]">SA</div>
          </div>
        </header>

        <nav className="flex gap-1 overflow-x-auto border-b border-[var(--hairline)] bg-[var(--surface)] px-3 py-2 lg:hidden">
          {NAV.map((item) => (
            <Link key={item.to} to={item.to}
              activeOptions={{ exact: item.to === "/" }}
              activeProps={{ className: "bg-primary/12 text-primary border-primary/30" }}
              inactiveProps={{ className: "text-muted-foreground border-transparent" }}
              className="shrink-0 rounded-md border px-3 py-1.5 text-xs whitespace-nowrap">
              {item.label}
            </Link>
          ))}
          <a href="/mitre/t1566.001"
            className="shrink-0 rounded-md border border-transparent px-3 py-1.5 text-xs whitespace-nowrap text-muted-foreground">
            MITRE ATT&amp;CK
          </a>
        </nav>

        <main className="min-w-0 flex-1 p-3 md:p-4">{children}</main>

        <footer className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-t border-[var(--hairline)] bg-[var(--surface)] px-4 py-2.5 md:px-6">
          <p className="truncate font-mono text-[0.62rem] text-muted-foreground">AISS v2.0.0 Â· AI Security Platform Â· {backendOnline ? "backend connected" : "backend offline"}</p>
          <p className="shrink-0 font-mono text-[0.62rem]" style={{ color: statusColor }}>{statusText}</p>
        </footer>
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, right }: {
  title: string; subtitle: string; right?: ReactNode;
}) {
  return (
    <div className="mb-3 grid grid-cols-[minmax(0,1fr)_auto] items-end gap-4 border-b border-[var(--hairline)] pb-3">
      <div className="min-w-0">
        <h1 className="truncate font-serif text-2xl font-bold">{title}</h1>
        <p className="mt-1 truncate text-sm text-muted-foreground">{subtitle}</p>
      </div>
      {right}
    </div>
  );
}
