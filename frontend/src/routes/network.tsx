import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { toast } from "sonner";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Bar, DataTable, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { AttackMap } from "@/components/soc/AttackMap";
import { PacketVisualizer } from "@/components/soc/PacketVisualizer";
import { useTopologyMap, useAgents, useAgentStats } from "@/hooks/useAISS";
import { generateAgentToken, addTopologySegment, scanAllNetworks } from "@/lib/api";
import type { Agent } from "@/lib/api";

export const Route = createFileRoute("/network")({
  head: () => ({
    meta: [
      { title: "Network Telemetry — AISS Security Console" },
      { name: "description", content: "Real-time network topology, agents, and traffic analytics" },
    ],
  }),
  component: NetworkPage,
});

function NetworkPage() {
  const { data: topology, refetch: refetchTopo }  = useTopologyMap();
  const { data: agentsData }                       = useAgents();
  const { data: agentStats }                       = useAgentStats();
  const [newToken, setNewToken]                    = useState<string | null>(null);
  const [addSegCidr, setAddSegCidr]                = useState("");
  const [addSegType, setAddSegType]                = useState("lan");
  const [scanning,   setScanning]                  = useState(false);

  const agents   = agentsData?.agents ?? [];
  const stats    = agentStats ?? { total: 0, connected: 0, disconnected: 0, by_network: { lan: 0, wan: 0, vpn: 0, man: 0 }, total_threats: 0 };
  const segments = topology?.segments ?? [];

  const handleGenToken = async () => {
    try {
      const r = await generateAgentToken("remote-agent");
      setNewToken(r.token);
      toast.success("Agent token generated — copy it below");
    } catch (e) { toast.error(String(e)); }
  };

  const handleAddSegment = async () => {
    if (!addSegCidr.trim()) return;
    try {
      await addTopologySegment(addSegCidr, addSegType, `${addSegType.toUpperCase()} — ${addSegCidr}`);
      toast.success(`Segment ${addSegCidr} added`);
      setAddSegCidr("");
      void refetchTopo();
    } catch (e) { toast.error(String(e)); }
  };

  const handleScan = async () => {
    setScanning(true);
    try {
      const r = await scanAllNetworks();
      toast.success(`Scan complete — ${r.total_hosts} host(s) found`);
      void refetchTopo();
    } catch (e) { toast.error(String(e)); }
    finally { setScanning(false); }
  };

  return (
    <div>
      <PageHeader
        title="Network Telemetry"
        subtitle="Topology map, remote agents, and perimeter analytics"
        right={
          <div className="flex gap-2">
            <ActionButton label={scanning ? "Scanning…" : "Scan Networks"} tone="info" onClick={() => void handleScan()} />
            <ActionButton label="Refresh Topology" onClick={() => void refetchTopo()} />
          </div>
        }
      />

      {/* Metrics */}
      <div className="mb-3 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Connected Agents" value={String(stats.connected)}   tone="success" sub={`${stats.total} total`} />
        <Metric label="Network Segments" value={String(segments.length)}   tone="info"    sub="monitored" />
        <Metric label="Threats (Agents)" value={String(stats.total_threats)} tone={stats.total_threats > 0 ? "critical" : "success"} sub="forwarded" />
        <Metric label="Topology Nodes"   value={String(topology?.node_count ?? 0)} tone="default" sub="discovered" />
      </div>

      {/* Attack map + packet viz */}
      <div className="mb-3 grid gap-3 xl:grid-cols-3">
        <div className="xl:col-span-2"><AttackMap /></div>
        <PacketVisualizer />
      </div>

      {/* Network by type */}
      <div className="mb-3 grid gap-3 xl:grid-cols-4">
        {(["lan","wan","vpn","man"] as const).map((t) => (
          <div key={t} className="panel p-3 text-center">
            <p className="label-cap text-[0.55rem]">{t.toUpperCase()}</p>
            <p className="mt-1 font-mono text-2xl font-bold">{stats.by_network[t]}</p>
            <p className="text-[0.65rem] text-muted-foreground">agents</p>
          </div>
        ))}
      </div>

      <div className="grid gap-3 xl:grid-cols-12">
        {/* Remote Agents table */}
        <div className="xl:col-span-8">
          <Panel
            title="Remote Agents"
            right={
              <div className="flex gap-1.5">
                <Badge tone="success">{stats.connected} online</Badge>
                <ActionButton label="Generate Token" tone="success" className="px-1.5 py-0.5" onClick={() => void handleGenToken()} />
              </div>
            }
          >
            {agents.length === 0 ? (
              <div className="space-y-3 py-4">
                <p className="text-sm text-muted-foreground text-center">No agents connected yet.</p>
                <div className="rounded-md border border-[var(--hairline)] bg-white/3 p-3 font-mono text-xs text-muted-foreground">
                  <p className="text-foreground mb-1">Connect a remote machine:</p>
                  <p>1. Generate a token (button above)</p>
                  <p>2. On the remote machine run:</p>
                  <p className="mt-1 text-primary">python aiss_agent.py \</p>
                  <p className="text-primary pl-4">--server ws://THIS_SERVER_IP:8000 \</p>
                  <p className="text-primary pl-4">--token YOUR_TOKEN</p>
                  <p className="mt-1 text-[0.65rem]">Works over LAN · WAN · VPN · MAN</p>
                </div>
                {newToken && (
                  <div className="rounded-md border border-primary/30 bg-primary/10 p-3">
                    <p className="label-cap mb-1">Generated Token (copy now):</p>
                    <p className="font-mono text-xs text-primary break-all">{newToken}</p>
                  </div>
                )}
              </div>
            ) : (
              <>
                {newToken && (
                  <div className="mb-3 rounded-md border border-primary/30 bg-primary/10 p-2">
                    <p className="label-cap text-[0.55rem]">New Token</p>
                    <p className="font-mono text-xs text-primary break-all">{newToken}</p>
                  </div>
                )}
                <DataTable
                  columns={["Host", "IP", "OS", "Network", "CPU", "RAM", "Threats", "Status"]}
                  rows={agents.map((a: Agent) => [
                    <span className="font-mono text-xs">{a.hostname}</span>,
                    <span className="font-mono text-xs text-muted-foreground">{a.ip}</span>,
                    <span className="text-xs">{a.os_name}</span>,
                    <Badge tone={a.network_type === "lan" ? "success" : a.network_type === "vpn" ? "info" : "warning"}>{a.network_type.toUpperCase()}</Badge>,
                    <span className="font-mono text-xs">{a.cpu_percent.toFixed(1)}%</span>,
                    <span className="font-mono text-xs">{a.ram_percent.toFixed(1)}%</span>,
                    <Badge tone={a.threat_count > 0 ? "critical" : "success"}>{a.threat_count}</Badge>,
                    <Badge tone={a.status === "connected" ? "success" : "warning"}>{a.status}</Badge>,
                  ])}
                />
              </>
            )}
          </Panel>
        </div>

        {/* Network segments */}
        <div className="xl:col-span-4 flex flex-col gap-3">
          <Panel title="Network Segments" right={<span className="label-cap">{segments.length} registered</span>}>
            {segments.length === 0 ? (
              <p className="text-xs text-muted-foreground">No segments yet. Add one below.</p>
            ) : (
              <ul className="space-y-2">
                {segments.map((s) => (
                  <li key={s.id} className="rounded-md border border-[var(--hairline)] px-2.5 py-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-mono text-xs">{s.cidr}</span>
                      <Badge tone={s.type === "lan" ? "success" : s.type === "vpn" ? "info" : "warning"}>{s.type}</Badge>
                    </div>
                    <p className="mt-0.5 text-[0.65rem] text-muted-foreground">{s.label || s.cidr}</p>
                    <Bar value={Math.min(100, (s.nodes.length / 10) * 100)} tone="var(--teal)" />
                  </li>
                ))}
              </ul>
            )}
            {/* Add segment form */}
            <div className="mt-3 space-y-2 border-t border-[var(--hairline)] pt-3">
              <p className="label-cap text-[0.55rem]">Add Segment</p>
              <input
                className="w-full rounded-md border border-[var(--hairline)] bg-white/5 px-2.5 py-1.5 text-xs outline-none placeholder:text-muted-foreground focus:border-primary/50"
                placeholder="192.168.1.0/24"
                value={addSegCidr}
                onChange={(e) => setAddSegCidr(e.target.value)}
              />
              <select
                className="w-full rounded-md border border-[var(--hairline)] bg-[#0f1a16] px-2.5 py-1.5 text-xs text-foreground"
                value={addSegType}
                onChange={(e) => setAddSegType(e.target.value)}
              >
                {["lan","wan","vpn","man"].map((t) => <option key={t} value={t}>{t.toUpperCase()}</option>)}
              </select>
              <ActionButton label="Add Segment" tone="success" className="w-full justify-center" onClick={() => void handleAddSegment()} />
            </div>
          </Panel>
        </div>
      </div>
    </div>
  );
}
