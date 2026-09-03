/**
 * Network Monitor & Discovery — AISS
 * Real backend:
 *  - /api/network/connections  — live connections (psutil)
 *  - /api/live/network-stats   — real-time bandwidth
 *  - /api/network-discovery/hosts  — nmap host discovery
 *  - /api/network-discovery/ports  — nmap port scan
 *  - /api/network-discovery/scans  — scan history
 *  - /api/network-discovery/interfaces — local interfaces
 */
import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Network, Search, Loader2, RefreshCw, Shield, AlertTriangle } from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { getLiveNetworkStats, getNetworkConnections } from "@/lib/api";

const BASE = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const tok = localStorage.getItem("aiss_token") ?? "";
  const r = await fetch(`${BASE}${path}`, {
    ...opts,
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok}`, ...(opts.headers ?? {}) },
  });
  if (!r.ok) {
    const err = await r.json().catch(() => ({ detail: r.statusText })) as { detail?: string };
    throw new Error(err.detail ?? `HTTP ${r.status}`);
  }
  return r.json() as Promise<T>;
}

interface HostDiscoveryResult {
  target: string; hosts_found: number; hosts_up: number;
  hosts: Array<{ ip: string; hostname?: string; status: string; latency_ms?: number; mac?: string; vendor?: string }>;
  method: string; duration_secs: number; scan_id: string;
}

interface PortScanResult {
  target: string; open_ports: Array<{ port: number; service: string; banner?: string; protocol: string }>;
  total_scanned: number; duration_secs: number; scan_id: string;
}

interface LocalInterface {
  name: string; ip: string; mac?: string; speed?: number; mtu?: number; is_up: boolean;
}

interface ScanRecord {
  id: string; scan_type: string; target: string; status: string;
  hosts_found?: number; hosts_up?: number; open_ports_count?: number;
  duration_secs?: number; started_at: string; completed_at?: string; error_message?: string;
}

export const Route = createFileRoute("/network-monitor")({
  head: () => ({
    meta: [
      { title: "Network Monitor & Discovery — AISS" },
      { name: "description", content: "Live network monitoring, nmap host discovery and port scanning" },
    ],
  }),
  component: NetworkMonitorPage,
});

type ScanMode = "hosts" | "ports";

function NetworkMonitorPage() {
  const [mode, setMode]         = useState<ScanMode>("hosts");
  const [target, setTarget]     = useState("");
  const [ports, setPorts]       = useState("common");
  const [method, setMethod]     = useState("nmap");
  const [scanType, setScanType] = useState("connect");
  const [running, setRunning]   = useState(false);

  const [hostResult, setHostResult] = useState<HostDiscoveryResult | null>(null);
  const [portResult, setPortResult] = useState<PortScanResult | null>(null);

  const { data: netStats, refetch: refetchNet } = useQuery({
    queryKey: ["live-network-stats"],
    queryFn: getLiveNetworkStats,
    refetchInterval: 3000,
  });

  const { data: connections } = useQuery({
    queryKey: ["network-connections"],
    queryFn: getNetworkConnections,
    refetchInterval: 5000,
  });

  const { data: interfaces } = useQuery({
    queryKey: ["network-interfaces"],
    queryFn: () => apiFetch<{ interfaces: LocalInterface[]; count: number }>("/api/network-discovery/interfaces"),
    refetchInterval: 30_000,
  });

  const { data: scanHistory, refetch: refetchHistory } = useQuery({
    queryKey: ["scan-history"],
    queryFn: () => apiFetch<{ scans: ScanRecord[]; count: number }>("/api/network-discovery/scans?limit=20"),
    refetchInterval: 10_000,
  });

  const runScan = async () => {
    if (!target.trim()) { toast.error("Enter a target IP/CIDR/hostname"); return; }
    setRunning(true);
    setHostResult(null);
    setPortResult(null);
    try {
      if (mode === "hosts") {
        toast.info("Starting host discovery...", { description: `Target: ${target} using ${method}` });
        const r = await apiFetch<HostDiscoveryResult>("/api/network-discovery/hosts", {
          method: "POST",
          body: JSON.stringify({ target: target.trim(), method, timeout: 30 }),
        });
        setHostResult(r);
        toast.success(`Discovery complete: ${r.hosts_up} live host(s) found`);
      } else {
        toast.info("Starting port scan...", { description: `Target: ${target} ports: ${ports}` });
        const r = await apiFetch<PortScanResult>("/api/network-discovery/ports", {
          method: "POST",
          body: JSON.stringify({ target: target.trim(), ports, scan_type: scanType, timeout: 60, max_rate: 500 }),
        });
        setPortResult(r);
        toast.success(`Port scan complete: ${r.open_ports.length} open port(s)`);
      }
      void refetchHistory();
    } catch (e) {
      toast.error(`Scan failed: ${String(e)}`);
    } finally {
      setRunning(false);
    }
  };

  const dangerousPorts = new Set([21, 23, 135, 139, 445, 1433, 3389, 4444, 5900, 6379, 27017]);

  return (
    <div>
      <PageHeader
        title="Network Monitor & Discovery"
        subtitle="Live connection monitoring, nmap host discovery, and port scanning"
        right={
          <div className="flex items-center gap-2">
            <Badge tone="success">{netStats?.connections ?? 0} live connections</Badge>
            <Badge tone={netStats?.blocked && netStats.blocked > 0 ? "critical" : "info"}>
              {netStats?.blocked ?? 0} blocked
            </Badge>
          </div>
        }
      />

      {/* Real-time metrics */}
      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Connections"    value={String(netStats?.total_conns ?? 0)}     tone="info"    sub="total active" />
        <Metric label="Recv"           value={`${netStats?.recv_mb_s?.toFixed(2) ?? "0"} MB/s`}    tone="success" sub="inbound" />
        <Metric label="Sent"           value={`${netStats?.sent_mb_s?.toFixed(2) ?? "0"} MB/s`}    tone="info"    sub="outbound" />
        <Metric label="Interfaces"     value={String(interfaces?.count ?? "—")}        tone="default" sub="network adapters" />
      </div>

      <div className="grid gap-4 xl:grid-cols-12">
        {/* Scan control */}
        <div className="xl:col-span-4 flex flex-col gap-4">
          <Panel title="Network Scan">
            {/* Mode */}
            <div className="flex gap-1 mb-4">
              {(["hosts", "ports"] as ScanMode[]).map(m => (
                <button
                  key={m}
                  onClick={() => setMode(m)}
                  className={`flex-1 rounded border px-3 py-1.5 font-mono text-[0.62rem] uppercase transition-colors ${
                    mode === m ? "border-primary/40 bg-primary/12 text-primary" : "border-transparent text-muted-foreground hover:bg-white/5"
                  }`}
                >
                  {m === "hosts" ? "Host Discovery" : "Port Scan"}
                </button>
              ))}
            </div>

            <div className="space-y-3">
              <div>
                <label className="label-cap text-[0.6rem] text-muted-foreground">Target</label>
                <input
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  onKeyDown={e => e.key === "Enter" && void runScan()}
                  placeholder={mode === "hosts" ? "e.g. 192.168.1.0/24 or hostname" : "e.g. 192.168.1.1"}
                  className="mt-1 w-full rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 font-mono text-sm outline-none focus:border-primary/50"
                />
              </div>

              {mode === "hosts" && (
                <div>
                  <label className="label-cap text-[0.6rem] text-muted-foreground">Method</label>
                  <select
                    value={method}
                    onChange={e => setMethod(e.target.value)}
                    className="mt-1 w-full rounded-md border border-[var(--hairline)] bg-[#0f1a16] px-3 py-2 text-sm text-foreground"
                  >
                    <option value="nmap">nmap (most reliable)</option>
                    <option value="ping">ping (ICMP)</option>
                    <option value="arp">ARP (LAN only)</option>
                  </select>
                </div>
              )}

              {mode === "ports" && (
                <>
                  <div>
                    <label className="label-cap text-[0.6rem] text-muted-foreground">Ports</label>
                    <input
                      value={ports}
                      onChange={e => setPorts(e.target.value)}
                      placeholder="common, top100, 1-1024, 80,443,8080"
                      className="mt-1 w-full rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 font-mono text-sm outline-none focus:border-primary/50"
                    />
                  </div>
                  <div>
                    <label className="label-cap text-[0.6rem] text-muted-foreground">Scan Type</label>
                    <select
                      value={scanType}
                      onChange={e => setScanType(e.target.value)}
                      className="mt-1 w-full rounded-md border border-[var(--hairline)] bg-[#0f1a16] px-3 py-2 text-sm text-foreground"
                    >
                      <option value="connect">TCP Connect (no root)</option>
                      <option value="syn">SYN Stealth (root)</option>
                      <option value="udp">UDP (slow)</option>
                    </select>
                  </div>
                </>
              )}

              <button
                onClick={() => void runScan()}
                disabled={running}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-2.5 text-sm font-semibold text-white transition-colors hover:bg-primary/90 disabled:opacity-50"
              >
                {running ? <Loader2 className="size-4 animate-spin" /> : <Search className="size-4" />}
                {running ? (mode === "hosts" ? "Discovering..." : "Scanning...") : (mode === "hosts" ? "Discover Hosts" : "Scan Ports")}
              </button>
            </div>

            {running && (
              <div className="mt-3 rounded-lg border border-blue-400/20 bg-blue-400/5 p-3 text-sm text-blue-300">
                <div className="flex items-center gap-2 mb-1">
                  <Loader2 className="size-4 animate-spin" />
                  <span className="font-medium">{mode === "hosts" ? "Host discovery in progress..." : "Port scanning in progress..."}</span>
                </div>
                <p className="text-xs text-muted-foreground">This may take 30–120 seconds. nmap must be installed on the server.</p>
              </div>
            )}
          </Panel>

          {/* Local interfaces */}
          {interfaces && interfaces.interfaces.length > 0 && (
            <Panel title="Local Interfaces" right={<span className="label-cap">{interfaces.count} adapters</span>}>
              <ul className="space-y-2">
                {interfaces.interfaces.map((iface: LocalInterface, i) => (
                  <li key={i} className="flex items-center justify-between gap-2 rounded-md border border-[var(--hairline)] px-2.5 py-1.5">
                    <div>
                      <p className="font-mono text-xs font-medium">{iface.name}</p>
                      <p className="font-mono text-[0.6rem] text-muted-foreground">{iface.ip}</p>
                    </div>
                    <Badge tone={iface.is_up ? "success" : "warning"}>{iface.is_up ? "UP" : "DOWN"}</Badge>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>

        {/* Results + connections */}
        <div className="xl:col-span-8 space-y-4">
          {/* Host discovery results */}
          {hostResult && (
            <Panel
              title={`Host Discovery — ${hostResult.target}`}
              right={
                <div className="flex gap-2">
                  <Badge tone="success">{hostResult.hosts_up} live</Badge>
                  <Badge tone="default">{hostResult.hosts_found} found</Badge>
                  <Badge tone="info">{hostResult.duration_secs.toFixed(1)}s</Badge>
                </div>
              }
            >
              {hostResult.hosts_up === 0 ? (
                <div className="text-center py-6 text-muted-foreground">
                  <Network className="size-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No live hosts found in {hostResult.target}</p>
                  <p className="text-xs mt-1">Try a different method or check the target range</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[var(--hairline)]">
                        {["IP Address", "Hostname", "Status", "Latency", "MAC", "Vendor"].map(h => (
                          <th key={h} className="label-cap px-2.5 py-2 text-left text-[0.58rem]">{h}</th>
                        ))}
                        <th className="label-cap px-2.5 py-2 text-right text-[0.58rem]">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {hostResult.hosts.map((h, i) => (
                        <tr key={i} className="border-b border-[var(--hairline)] last:border-0 hover:bg-white/4">
                          <td className="px-2.5 py-2 font-mono text-xs">{h.ip}</td>
                          <td className="px-2.5 py-2 text-xs text-muted-foreground">{h.hostname ?? "—"}</td>
                          <td className="px-2.5 py-2"><Badge tone="success">{h.status}</Badge></td>
                          <td className="px-2.5 py-2 font-mono text-xs">{h.latency_ms != null ? `${h.latency_ms}ms` : "—"}</td>
                          <td className="px-2.5 py-2 font-mono text-[0.6rem] text-muted-foreground">{h.mac ?? "—"}</td>
                          <td className="px-2.5 py-2 text-xs text-muted-foreground">{h.vendor ?? "—"}</td>
                          <td className="px-2.5 py-2 text-right">
                            <ActionButton
                              label="Port Scan"
                              tone="info"
                              className="px-1.5 py-0.5 text-[0.58rem]"
                              onClick={() => { setMode("ports"); setTarget(h.ip); }}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </Panel>
          )}

          {/* Port scan results */}
          {portResult && (
            <Panel
              title={`Port Scan — ${portResult.target}`}
              right={
                <div className="flex gap-2">
                  <Badge tone={portResult.open_ports.length > 0 ? "warning" : "success"}>
                    {portResult.open_ports.length} open
                  </Badge>
                  <Badge tone="info">{portResult.duration_secs.toFixed(1)}s</Badge>
                </div>
              }
            >
              {portResult.open_ports.length === 0 ? (
                <div className="text-center py-6 text-muted-foreground">
                  <Shield className="size-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">No open ports found on {portResult.target}</p>
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[var(--hairline)]">
                        {["Port", "Protocol", "Service", "Banner", "Risk"].map(h => (
                          <th key={h} className="label-cap px-2.5 py-2 text-left text-[0.58rem]">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {portResult.open_ports.map((p, i) => {
                        const isDangerous = dangerousPorts.has(p.port);
                        return (
                          <tr key={i} className={`border-b border-[var(--hairline)] last:border-0 hover:bg-white/4 ${isDangerous ? "bg-red-400/3" : ""}`}>
                            <td className="px-2.5 py-2">
                              <div className="flex items-center gap-1.5">
                                {isDangerous && <AlertTriangle className="size-3 text-red-400 shrink-0" />}
                                <span className="font-mono text-xs font-semibold">{p.port}</span>
                              </div>
                            </td>
                            <td className="px-2.5 py-2">
                              <Badge tone="default">{p.protocol.toUpperCase()}</Badge>
                            </td>
                            <td className="px-2.5 py-2 font-mono text-xs">{p.service}</td>
                            <td className="px-2.5 py-2 font-mono text-[0.62rem] text-muted-foreground max-w-[200px] truncate">
                              {p.banner ?? "—"}
                            </td>
                            <td className="px-2.5 py-2">
                              <Badge tone={isDangerous ? "critical" : "success"}>
                                {isDangerous ? "HIGH RISK" : "NORMAL"}
                              </Badge>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  {portResult.open_ports.some(p => dangerousPorts.has(p.port)) && (
                    <div className="mt-3 rounded-lg border border-red-400/30 bg-red-400/5 p-3 text-sm text-red-300">
                      <AlertTriangle className="size-4 inline mr-1.5" />
                      High-risk ports detected. These ports are commonly exploited by attackers.
                    </div>
                  )}
                </div>
              )}
            </Panel>
          )}

          {/* Live connections */}
          <Panel
            title="Live Connections"
            right={
              <div className="flex items-center gap-2">
                <Badge tone="info">{connections?.connections.length ?? 0} connections</Badge>
                <ActionButton label="Refresh" className="px-1.5 py-0.5" onClick={() => void refetchNet()} />
              </div>
            }
          >
            {(connections?.connections.length ?? 0) === 0 ? (
              <p className="text-sm text-muted-foreground py-4 text-center">No connections data</p>
            ) : (
              <div className="overflow-x-auto max-h-64">
                <table className="w-full text-sm">
                  <thead className="sticky top-0 bg-[var(--surface)]">
                    <tr className="border-b border-[var(--hairline)]">
                      {["Local Address", "Remote Address", "Status", "PID"].map(h => (
                        <th key={h} className="label-cap px-2.5 py-2 text-left text-[0.58rem]">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {connections?.connections.slice(0, 50).map((c, i) => (
                      <tr key={i} className="border-b border-[var(--hairline)] last:border-0 hover:bg-white/4">
                        <td className="px-2.5 py-1.5 font-mono text-[0.65rem]">{c.local_address}</td>
                        <td className="px-2.5 py-1.5 font-mono text-[0.65rem] text-muted-foreground">{c.remote_address || "—"}</td>
                        <td className="px-2.5 py-1.5">
                          <Badge tone={c.status === "ESTABLISHED" ? "success" : c.status === "LISTEN" ? "info" : "default"}>
                            {c.status}
                          </Badge>
                        </td>
                        <td className="px-2.5 py-1.5 font-mono text-[0.62rem] text-muted-foreground">{c.pid ?? "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Panel>

          {/* Scan history */}
          {scanHistory && scanHistory.scans.length > 0 && (
            <Panel title="Scan History" right={<span className="label-cap">{scanHistory.count} total</span>}>
              <div className="space-y-1.5">
                {scanHistory.scans.map((s: ScanRecord) => (
                  <div key={s.id} className="flex items-center gap-3 rounded-md border border-[var(--hairline)] px-3 py-1.5">
                    <Badge tone={s.status === "completed" ? "success" : s.status === "failed" ? "critical" : "warning"}>
                      {s.status}
                    </Badge>
                    <span className="font-mono text-xs flex-1 truncate">{s.target}</span>
                    <span className="text-xs text-muted-foreground shrink-0">{s.scan_type}</span>
                    {s.hosts_up != null && <span className="font-mono text-[0.6rem] text-muted-foreground shrink-0">{s.hosts_up} up</span>}
                    {s.open_ports_count != null && <span className="font-mono text-[0.6rem] text-muted-foreground shrink-0">{s.open_ports_count} ports</span>}
                    <span className="font-mono text-[0.55rem] text-muted-foreground shrink-0">
                      {new Date(s.started_at).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}
