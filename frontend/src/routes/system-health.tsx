import { createFileRoute } from "@tanstack/react-router";
import { useSystemHealth, useLibraries, useLLMProviders } from "@/hooks/useAISS";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Bar, Metric } from "@/components/soc/ui";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

export const Route = createFileRoute("/system-health")({
  head: () => ({
    meta: [
      { title: "System Health — AISS Security Operations" },
      { name: "description", content: "Real-time platform component status" },
    ],
  }),
  component: SystemHealthPage,
});

function SystemHealthPage() {
  const { data: health }    = useSystemHealth();
  const { data: libData }   = useLibraries();
  const { data: llmData }   = useLLMProviders();

  // Fall back to ModulePage if no live data yet
  if (!health) return <ModulePage m={MODULES["system-health"]!} />;

  const libs     = libData?.libraries ?? [];
  const enabled  = libs.filter((l) => l.enabled);
  const disabled = libs.filter((l) => !l.enabled);

  return (
    <div>
      <PageHeader
        title="System Health"
        subtitle="Real-time AISS platform status — live data from backend"
        right={
          <Badge tone={health.cpu_percent < 80 ? "success" : "warning"}>
            {health.cpu_percent < 80 ? "NOMINAL" : "HIGH LOAD"}
          </Badge>
        }
      />

      <div className="flex flex-col gap-3">
        {/* Metrics */}
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
          <Metric label="Uptime"       value={`${Math.floor(health.uptime_secs / 3600)}h`} tone="success" sub={`${health.uptime_secs}s`} />
          <Metric label="CPU"          value={`${health.cpu_percent.toFixed(1)}%`} tone={health.cpu_percent > 80 ? "critical" : "info"} sub="cluster" />
          <Metric label="RAM"          value={`${health.ram_percent.toFixed(1)}%`} tone={health.ram_percent > 85 ? "warning" : "info"} sub={`${health.ram_used_mb}MB used`} />
          <Metric label="Disk"         value={`${health.disk_percent.toFixed(1)}%`} tone={health.disk_percent > 80 ? "warning" : "success"} sub="hot tier" />
          <Metric label="Processes"    value={String(health.process_count)} tone="default" sub="running" />
          <Metric label="Libraries"    value={`${libData?.enabled ?? "…"}/${libData?.total ?? "…"}`} tone="success" sub="integrated" />
        </div>

        {/* Resource bars */}
        <Panel title="Resource Utilisation" right={<span className="label-cap">live</span>}>
          <div className="space-y-3">
            {[
              ["CPU", health.cpu_percent, health.cpu_percent > 80 ? "var(--critical)" : "var(--teal)"],
              ["RAM", health.ram_percent, health.ram_percent > 85 ? "var(--warning)" : "var(--teal)"],
              ["Disk", health.disk_percent, health.disk_percent > 80 ? "var(--warning)" : "var(--teal)"],
              ["Net Sent", Math.min(100, health.net_sent_mb / 10), "var(--cyan)"],
              ["Net Recv", Math.min(100, health.net_recv_mb / 10), "var(--cyan)"],
            ].map(([label, value, tone]) => (
              <div key={label as string} className="grid grid-cols-[8rem_minmax(0,1fr)_4rem] items-center gap-3">
                <span className="label-cap">{label as string}</span>
                <Bar value={value as number} tone={tone as string} />
                <span className="text-right font-mono text-xs">{Math.round(value as number)}%</span>
              </div>
            ))}
          </div>
        </Panel>

        {/* LLM Providers */}
        <div className="grid gap-3 lg:grid-cols-2">
          <Panel title="LLM Providers" right={<Badge tone="info">{llmData?.total_providers ?? 0} active</Badge>}>
            {llmData?.providers.length ? (
              <ul className="space-y-1.5">
                {llmData.providers.map((p) => (
                  <li key={p} className="flex items-center gap-2">
                    <span className="size-2 rounded-full bg-[var(--success)]" />
                    <span className="text-xs">{p}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-xs text-muted-foreground">No LLM providers configured. Add API keys in settings.</p>
            )}
          </Panel>

          {/* Module health */}
          <Panel title="Detection Modules" right={<Badge tone="success">live</Badge>}>
            <ul className="space-y-1.5">
              {Object.entries(health.modules).map(([mod, ok]) => (
                <li key={mod} className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2">
                  <span className="text-xs text-muted-foreground capitalize">{mod.replace(/_/g, " ")}</span>
                  <Badge tone={ok ? "success" : "critical"}>{ok ? "online" : "offline"}</Badge>
                </li>
              ))}
            </ul>
          </Panel>
        </div>

        {/* Library integrations */}
        {libs.length > 0 && (
          <Panel
            title="Library Integrations"
            right={
              <div className="flex gap-2">
                <Badge tone="success">{enabled.length} enabled</Badge>
                <Badge tone="warning">{disabled.length} disabled</Badge>
              </div>
            }
          >
            <div className="grid gap-1.5 sm:grid-cols-2 xl:grid-cols-3">
              {libs.map((lib) => (
                <div
                  key={lib.name}
                  className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-2 rounded-md border border-[var(--hairline)] px-2.5 py-1.5"
                >
                  <div className="min-w-0">
                    <p className="truncate font-mono text-[0.68rem]">{lib.name}</p>
                    {lib.version && <p className="truncate text-[0.6rem] text-muted-foreground">{lib.version}</p>}
                  </div>
                  <span
                    className="size-2 shrink-0 rounded-full"
                    style={{ background: lib.enabled ? "var(--success)" : "var(--hairline)" }}
                  />
                </div>
              ))}
            </div>
          </Panel>
        )}
      </div>
    </div>
  );
}
