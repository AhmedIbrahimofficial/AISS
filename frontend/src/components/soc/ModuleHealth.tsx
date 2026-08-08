import { Panel } from "./Panel";
import { C } from "./data";
import { useSystemHealth } from "@/hooks/useAISS";

export function ModuleHealth() {
  const { data: health, isLoading } = useSystemHealth();

  // Build module list from real backend data
  const modules = health?.modules
    ? Object.entries(health.modules).map(([name, active]) => ({
        name: name.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase()),
        active: active as boolean,
      }))
    : [];

  // Fallback static list while loading
  const fallback = [
    { name: "Network Monitor", active: false },
    { name: "Auth Monitor", active: false },
    { name: "File Monitor", active: false },
    { name: "Malware Scanner", active: false },
    { name: "AI Firewall", active: false },
  ];

  const items = modules.length > 0 ? modules : fallback;

  return (
    <Panel title="Module Health" right={
      health
        ? <span className="label-cap text-[var(--success)]">BACKEND ONLINE</span>
        : <span className="label-cap text-muted-foreground">{isLoading ? "connecting..." : "offline"}</span>
    }>
      {/* System stats row */}
      {health && (
        <div className="mb-3 grid grid-cols-3 gap-2 text-center">
          <div className="rounded border border-[var(--hairline)] p-2">
            <p className="font-mono text-sm font-bold" style={{ color: health.cpu_percent > 80 ? C.critical : C.teal }}>
              {Math.round(health.cpu_percent)}%
            </p>
            <p className="label-cap text-[0.55rem]">CPU</p>
          </div>
          <div className="rounded border border-[var(--hairline)] p-2">
            <p className="font-mono text-sm font-bold" style={{ color: health.ram_percent > 85 ? C.critical : C.teal }}>
              {Math.round(health.ram_percent)}%
            </p>
            <p className="label-cap text-[0.55rem]">RAM</p>
          </div>
          <div className="rounded border border-[var(--hairline)] p-2">
            <p className="font-mono text-sm font-bold" style={{ color: health.disk_percent > 90 ? C.critical : C.success }}>
              {Math.round(health.disk_percent)}%
            </p>
            <p className="label-cap text-[0.55rem]">DISK</p>
          </div>
        </div>
      )}

      <div className="flex flex-1 flex-col justify-between gap-3">
        {items.map((m) => (
          <div key={m.name} className="min-w-0">
            <div className="mb-1.5 flex items-center justify-between">
              <span className="truncate text-xs text-[#E6EDEA]">{m.name}</span>
              <span className="font-mono text-[0.6rem] tracking-widest"
                style={{ color: m.active ? C.success : C.warning }}>
                {m.active ? "ACTIVE" : isLoading ? "..." : "OFFLINE"}
              </span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-[rgba(255,255,255,0.06)]">
              <div className="h-full rounded-full transition-all duration-700"
                style={{
                  width: m.active ? "100%" : "0%",
                  background: m.active
                    ? `linear-gradient(90deg, ${C.teal}, ${C.success})`
                    : `linear-gradient(90deg, ${C.warning}, ${C.warning})`,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </Panel>
  );
}
