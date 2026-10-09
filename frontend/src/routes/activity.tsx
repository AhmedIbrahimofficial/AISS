import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import {
  Cpu, Network, FileSearch, Shield, Activity, AlertTriangle,
  CheckCircle2, RefreshCw, Globe, Lock,
} from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { useQuery } from "@tanstack/react-query";
import {
  getLiveProcesses, getLiveFiles, getLiveNetworkStats,
  getNetworkConnections, type LiveProcess, type NetworkConnection,
} from "@/lib/api";
import { useBackendStatus } from "@/hooks/useAISS";

export const Route = createFileRoute("/activity")({
  head: () => ({
    meta: [{ title: "Activity — AISS" }],
  }),
  component: ActivityPage,
});

// ─────────────────────────────────────────────────────────────────────────────
// Process Row
// ─────────────────────────────────────────────────────────────────────────────
function ProcessRow({ proc }: { proc: LiveProcess }) {
  const cpuColor =
    proc.cpu > 80 ? "var(--critical)"
    : proc.cpu > 40 ? "var(--warning)"
    : "var(--success)";

  return (
    <tr
      className={`border-b border-[var(--hairline)] text-sm transition-colors hover:bg-white/2 ${
        proc.suspicious ? "bg-[var(--critical)]/5" : ""
      }`}
    >
      <td className="py-2 pr-4">
        <div className="flex items-center gap-2">
          {proc.suspicious ? (
            <AlertTriangle className="size-3.5 shrink-0 text-[var(--critical)]" />
          ) : (
            <div className="size-3.5 shrink-0 rounded-full border border-[var(--success)]/30 bg-[var(--success)]/10" />
          )}
          <span
            className={`font-mono text-xs ${proc.suspicious ? "text-[var(--critical)]" : ""}`}
          >
            {proc.name}
          </span>
        </div>
      </td>
      <td className="py-2 pr-4 font-mono text-xs text-muted-foreground">{proc.pid}</td>
      <td className="py-2 pr-4">
        <div className="flex items-center gap-2">
          <div className="h-1.5 w-16 overflow-hidden rounded-full bg-white/8">
            <div
              className="h-full rounded-full"
              style={{ width: `${Math.min(proc.cpu, 100)}%`, background: cpuColor }}
            />
          </div>
          <span className="font-mono text-xs" style={{ color: cpuColor }}>
            {proc.cpu.toFixed(1)}%
          </span>
        </div>
      </td>
      <td className="py-2 pr-4 font-mono text-xs text-muted-foreground">
        {proc.mem.toFixed(1)}%
      </td>
      <td className="py-2 font-mono text-[0.65rem] text-muted-foreground max-w-[200px] truncate">
        {proc.user}
      </td>
    </tr>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection Row
// ─────────────────────────────────────────────────────────────────────────────
function ConnectionRow({ conn }: { conn: NetworkConnection }) {
  const statusColor =
    conn.status === "ESTABLISHED" ? "var(--success)"
    : conn.status === "LISTEN" ? "var(--cyan)"
    : "var(--muted-foreground)";

  return (
    <tr className="border-b border-[var(--hairline)] text-sm hover:bg-white/2 transition-colors">
      <td className="py-2 pr-4 font-mono text-xs">{conn.local_address}</td>
      <td className="py-2 pr-4 font-mono text-xs text-muted-foreground">
        {conn.remote_address || "—"}
      </td>
      <td className="py-2 pr-4">
        <span
          className="font-mono text-[0.6rem] font-semibold tracking-wider"
          style={{ color: statusColor }}
        >
          {conn.status}
        </span>
      </td>
      <td className="py-2 font-mono text-xs text-muted-foreground">{conn.pid ?? "—"}</td>
    </tr>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Panel wrapper
// ─────────────────────────────────────────────────────────────────────────────
function Section({
  title,
  icon: Icon,
  children,
  badge,
  warning,
  refetch,
}: {
  title: string;
  icon: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  badge?: string;
  warning?: number;
  refetch?: () => void;
}) {
  return (
    <div className="panel overflow-hidden">
      <div className="flex items-center justify-between border-b border-[var(--hairline)] px-4 py-3">
        <div className="flex items-center gap-2.5">
          <Icon className="size-4 text-primary" />
          <p className="text-sm font-semibold">{title}</p>
          {badge && (
            <span className="rounded-md border border-[var(--hairline)] px-2 py-0.5 font-mono text-[0.6rem] text-muted-foreground">
              {badge}
            </span>
          )}
          {warning != null && warning > 0 && (
            <span className="flex items-center gap-1 rounded-md border border-[var(--critical)]/30 bg-[var(--critical)]/10 px-2 py-0.5 font-mono text-[0.6rem] text-[var(--critical)]">
              <AlertTriangle className="size-2.5" /> {warning} suspicious
            </span>
          )}
        </div>
        {refetch && (
          <button
            onClick={refetch}
            className="rounded-md p-1 text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="size-3.5" />
          </button>
        )}
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Activity Page
// ─────────────────────────────────────────────────────────────────────────────
function ActivityPage() {
  const { online } = useBackendStatus();
  const [tab, setTab] = useState<"processes" | "network" | "files" | "auth">("processes");

  const procs = useQuery({
    queryKey: ["live-processes"],
    queryFn: getLiveProcesses,
    refetchInterval: 8_000,
    enabled: online,
  });

  const netStats = useQuery({
    queryKey: ["live-network-stats"],
    queryFn: getLiveNetworkStats,
    refetchInterval: 5_000,
    enabled: online,
  });

  const conns = useQuery({
    queryKey: ["network-connections"],
    queryFn: getNetworkConnections,
    refetchInterval: 10_000,
    enabled: online && tab === "network",
  });

  const files = useQuery({
    queryKey: ["live-files"],
    queryFn: getLiveFiles,
    refetchInterval: 15_000,
    enabled: online && tab === "files",
  });

  const processes = procs.data?.processes ?? [];
  const suspicious = procs.data?.suspicious_count ?? 0;

  const TABS = [
    { id: "processes" as const, label: "Processes", icon: Cpu, count: processes.length },
    { id: "network"   as const, label: "Network",   icon: Network, count: conns.data?.connections?.length ?? netStats.data?.connections },
    { id: "files"     as const, label: "Files",      icon: FileSearch, count: files.data?.total_found },
    { id: "auth"      as const, label: "Auth",        icon: Shield, count: null },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Activity"
        subtitle="Real-time view of processes, network, files, and authentication"
        right={
          <div className="flex items-center gap-2">
            {suspicious > 0 && (
              <span className="flex items-center gap-1.5 rounded-lg border border-[var(--warning)]/30 bg-[var(--warning)]/10 px-3 py-1.5 text-xs text-[var(--warning)]">
                <AlertTriangle className="size-3.5" />
                {suspicious} suspicious process{suspicious !== 1 ? "es" : ""}
              </span>
            )}
            {netStats.data && (
              <span className="flex items-center gap-1.5 rounded-lg border border-[var(--hairline)] bg-white/3 px-3 py-1.5 text-xs text-muted-foreground">
                <Activity className="size-3.5" />
                {netStats.data.connections} connections
              </span>
            )}
          </div>
        }
      />

      {/* Network stats strip */}
      {online && netStats.data && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            { label: "Active Connections", value: netStats.data.connections, color: "var(--cyan)", icon: Network },
            { label: "Listening Ports",    value: netStats.data.listening,    color: "var(--success)", icon: Lock },
            { label: "Download",           value: `${netStats.data.recv_mb_s?.toFixed(1) ?? "0"} MB/s`, color: "var(--warning)", icon: Globe },
            { label: "Upload",             value: `${netStats.data.sent_mb_s?.toFixed(1) ?? "0"} MB/s`, color: "var(--primary)", icon: Globe },
          ].map((kpi) => (
            <div key={kpi.label} className="panel flex items-center gap-3 px-4 py-3">
              <kpi.icon className="size-5 shrink-0" style={{ color: kpi.color }} />
              <div>
                <p className="font-mono text-lg font-bold" style={{ color: kpi.color }}>
                  {kpi.value}
                </p>
                <p className="label-cap text-[0.58rem]">{kpi.label}</p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tab bar */}
      <div className="flex gap-1 rounded-xl border border-[var(--hairline)] bg-black/20 p-1 w-fit">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-all ${
              tab === t.id
                ? "bg-primary/15 text-primary border border-primary/30"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <t.icon className="size-4" />
            {t.label}
            {t.count != null && (
              <span className="rounded-md bg-white/8 px-1.5 py-0.5 font-mono text-[0.6rem]">
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {!online && (
        <div className="panel flex flex-col items-center gap-3 py-12 text-center">
          <Shield className="size-10 text-muted-foreground opacity-20" />
          <p className="text-sm text-muted-foreground">
            Backend offline. Start the backend to view live activity.
          </p>
        </div>
      )}

      {/* ── Processes Tab ──────────────────────────────────────────── */}
      {online && tab === "processes" && (
        <Section
          title="Running Processes"
          icon={Cpu}
          badge={`${processes.length} total`}
          warning={suspicious}
          refetch={() => procs.refetch()}
        >
          {procs.isLoading ? (
            <div className="flex items-center justify-center gap-2 py-8 text-muted-foreground">
              <RefreshCw className="size-4 animate-spin" /> Loading processes…
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left">
                    {["Process", "PID", "CPU", "Memory", "User"].map((h) => (
                      <th
                        key={h}
                        className="pb-2 pr-4 label-cap text-[0.6rem] text-muted-foreground"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {processes.slice(0, 50).map((p) => (
                    <ProcessRow key={p.pid} proc={p} />
                  ))}
                </tbody>
              </table>
              {processes.length > 50 && (
                <p className="mt-2 text-center text-[0.72rem] text-muted-foreground">
                  Showing 50 of {processes.length} processes
                </p>
              )}
            </div>
          )}
        </Section>
      )}

      {/* ── Network Tab ────────────────────────────────────────────── */}
      {online && tab === "network" && (
        <Section
          title="Network Connections"
          icon={Network}
          badge={`${conns.data?.connections?.length ?? 0} active`}
          refetch={() => conns.refetch()}
        >
          {conns.isLoading ? (
            <div className="flex items-center justify-center gap-2 py-8 text-muted-foreground">
              <RefreshCw className="size-4 animate-spin" /> Loading connections…
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="text-left">
                    {["Local", "Remote", "Status", "PID"].map((h) => (
                      <th
                        key={h}
                        className="pb-2 pr-4 label-cap text-[0.6rem] text-muted-foreground"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(conns.data?.connections ?? []).slice(0, 60).map((c, i) => (
                    <ConnectionRow key={i} conn={c} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Section>
      )}

      {/* ── Files Tab ─────────────────────────────────────────────── */}
      {online && tab === "files" && (
        <Section
          title="Recent File Activity"
          icon={FileSearch}
          badge={`${files.data?.total_found ?? 0} scanned`}
          warning={files.data?.suspicious_count}
          refetch={() => files.refetch()}
        >
          {files.isLoading ? (
            <div className="flex items-center justify-center gap-2 py-8 text-muted-foreground">
              <RefreshCw className="size-4 animate-spin" /> Scanning files…
            </div>
          ) : (
            <div className="space-y-1">
              {/* Suspicious files first */}
              {(files.data?.suspicious ?? []).map((f) => (
                <div
                  key={f.path}
                  className="flex items-center gap-3 rounded-lg border border-[var(--critical)]/20 bg-[var(--critical)]/6 px-3 py-2.5"
                >
                  <AlertTriangle className="size-4 shrink-0 text-[var(--critical)]" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-xs font-semibold text-[var(--critical)]">
                      {f.name}
                    </p>
                    <p className="truncate font-mono text-[0.6rem] text-muted-foreground">
                      {f.path}
                    </p>
                  </div>
                  <span className="shrink-0 font-mono text-[0.6rem] text-muted-foreground">
                    {(f.size / 1024).toFixed(0)} KB
                  </span>
                </div>
              ))}
              {/* Normal files */}
              {(files.data?.files ?? []).slice(0, 30).map((f) => (
                <div
                  key={f.path}
                  className="flex items-center gap-3 rounded-lg px-3 py-2 hover:bg-white/2 transition-colors"
                >
                  <CheckCircle2 className="size-4 shrink-0 text-[var(--success)]/40" />
                  <div className="min-w-0 flex-1">
                    <p className="truncate font-mono text-xs">{f.name}</p>
                    <p className="truncate font-mono text-[0.6rem] text-muted-foreground">
                      {f.dir}
                    </p>
                  </div>
                  <span className="shrink-0 font-mono text-[0.6rem] text-muted-foreground">
                    {(f.size / 1024).toFixed(0)} KB
                  </span>
                </div>
              ))}
              {!files.data?.files?.length && !files.data?.suspicious?.length && (
                <p className="py-8 text-center text-sm text-muted-foreground">
                  No file activity detected yet.
                </p>
              )}
            </div>
          )}
        </Section>
      )}

      {/* ── Auth Tab ──────────────────────────────────────────────── */}
      {online && tab === "auth" && (
        <Section title="Authentication Events" icon={Shield}>
          <div className="flex flex-col items-center gap-3 py-10 text-center">
            <Lock className="size-10 text-muted-foreground opacity-20" />
            <p className="text-sm text-muted-foreground">
              Auth event stream active. Events appear when login activity is detected.
            </p>
            <p className="text-[0.72rem] text-muted-foreground max-w-sm">
              AISS monitors failed logins, lockouts, credential stuffing patterns,
              privilege escalation, and suspicious session behavior in real time.
            </p>
          </div>
        </Section>
      )}
    </div>
  );
}
