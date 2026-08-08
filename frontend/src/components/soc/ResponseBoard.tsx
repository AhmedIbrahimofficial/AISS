import { Panel } from "./Panel";
import { C } from "./data";
import { useThreatStats } from "@/hooks/useAISS";

export function ResponseBoard() {
  const { data: stats } = useThreatStats();

  const COLUMNS = [
    { name: "Active",      color: C.critical, value: stats?.active    ?? 0 },
    { name: "Critical",    color: C.warning,  value: stats?.critical  ?? 0 },
    { name: "High",        color: C.cyan,     value: stats?.high      ?? 0 },
    { name: "Medium",      color: C.campaign, value: stats?.medium    ?? 0 },
    { name: "Low",         color: C.teal,     value: stats?.low       ?? 0 },
    { name: "Resolved",    color: C.success,  value: stats?.resolved  ?? 0 },
  ];

  return (
    <Panel title="Response Status Board" right={
      <span className="label-cap">
        {stats ? `${stats.total} total` : "loading..."}
      </span>
    }>
      <div className="grid flex-1 auto-rows-fr grid-cols-2 gap-2 lg:grid-cols-3">
        {COLUMNS.map((col) => (
          <div
            key={col.name}
            className="flex flex-col justify-center rounded-lg border p-3 transition-colors"
            style={{
              borderColor: `color-mix(in oklab, ${col.color} 25%, transparent)`,
              background: `color-mix(in oklab, ${col.color} 7%, transparent)`,
            }}
          >
            <p className="label-cap truncate">{col.name}</p>
            <p className="mt-1 font-mono text-2xl font-bold" style={{ color: col.color }}>
              {col.value}
            </p>
          </div>
        ))}
      </div>
    </Panel>
  );
}
