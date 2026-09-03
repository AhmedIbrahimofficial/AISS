/**
 * Live System Overview — disk partitions + network I/O
 * All data is real, pulled from /api/live/disk and /api/live/network-stats
 */
import { useQuery } from "@tanstack/react-query";
import { getLiveDisk, getLiveNetworkStats } from "@/lib/api";
import { Panel } from "./Panel";
import { Bar } from "./ui";
import { C } from "./data";

export function LiveDiskPanel() {
  const { data } = useQuery({
    queryKey: ["live-disk"],
    queryFn: getLiveDisk,
    refetchInterval: 15_000,
  });

  const parts = data?.partitions ?? [];

  return (
    <Panel title="Disk Partitions" right={<span className="label-cap">{parts.length} drives</span>}>
      {parts.length === 0 ? (
        <div className="flex h-20 items-center justify-center">
          <div className="size-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      ) : (
        <ul className="flex flex-1 flex-col justify-between gap-2">
          {parts.map((p) => (
            <li key={p.mountpoint}>
              <div className="mb-1 grid grid-cols-[auto_minmax(0,1fr)_auto_auto] items-center gap-2">
                <span className="rounded border border-[var(--hairline)] bg-white/4 px-1.5 py-0.5 font-mono text-[0.58rem]">
                  {p.device.split(/[/\\]/).pop()}
                </span>
                <span className="truncate font-mono text-[0.62rem] text-muted-foreground">{p.mountpoint}</span>
                <span className="font-mono text-[0.62rem] text-muted-foreground">{p.used_gb}GB / {p.total_gb}GB</span>
                <span className="font-mono text-xs font-semibold" style={{
                  color: p.percent > 90 ? C.critical : p.percent > 75 ? C.warning : C.teal
                }}>
                  {p.percent}%
                </span>
              </div>
              <Bar
                value={p.percent}
                tone={p.percent > 90 ? "var(--critical)" : p.percent > 75 ? "var(--warning)" : "var(--teal)"}
              />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}

export function LiveNetworkIOPanel() {
  const { data } = useQuery({
    queryKey: ["live-network-stats"],
    queryFn: getLiveNetworkStats,
    refetchInterval: 4000,
  });

  const stats = [
    { label: "Active Connections", value: String(data?.connections ?? "—"), color: C.teal },
    { label: "Listening Ports",    value: String(data?.listening   ?? "—"), color: C.cyan },
    { label: "Blocked/Closing",    value: String(data?.blocked     ?? "—"), color: data?.blocked ? C.warning : C.success },
    { label: "Total Connections",  value: String(data?.total_conns ?? "—"), color: C.muted },
    { label: "Recv Speed",         value: data ? `${data.recv_mb_s.toFixed(2)} MB/s` : "—", color: C.teal },
    { label: "Send Speed",         value: data ? `${data.sent_mb_s.toFixed(2)} MB/s` : "—", color: C.campaign },
    { label: "Total Received",     value: data ? `${data.total_recv_mb.toFixed(0)} MB` : "—", color: C.muted },
    { label: "Total Sent",         value: data ? `${data.total_sent_mb.toFixed(0)} MB` : "—", color: C.muted },
  ];

  return (
    <Panel
      title="Network I/O"
      right={<span className="dot-pulse size-2 bg-[var(--teal)] text-[var(--teal)]" />}
    >
      <div className="grid grid-cols-2 gap-2 flex-1">
        {stats.map((s) => (
          <div key={s.label} className="rounded-md border border-[var(--hairline)] bg-white/3 px-2.5 py-2">
            <p className="label-cap truncate text-[0.52rem]">{s.label}</p>
            <p className="mt-1 font-mono text-sm font-bold" style={{ color: s.color }}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Interface list */}
      {data?.interfaces && data.interfaces.length > 0 && (
        <div className="mt-2 border-t border-[var(--hairline)] pt-2">
          <p className="label-cap mb-1.5 text-[0.52rem]">Interfaces</p>
          <div className="flex flex-wrap gap-1">
            {data.interfaces.map((iface) => (
              <span
                key={iface.name}
                className="rounded border px-1.5 py-0.5 font-mono text-[0.55rem]"
                style={{
                  borderColor: iface.up ? "rgba(16,185,129,0.3)" : "rgba(255,255,255,0.1)",
                  color: iface.up ? C.success : C.muted,
                }}
              >
                {iface.name} {iface.speed > 0 ? `${iface.speed}M` : ""}
              </span>
            ))}
          </div>
        </div>
      )}
    </Panel>
  );
}
