/**
 * Threat Density Heatmap — 7d × 24h grid
 * Maps real threat data to their detected_at hour/day slot.
 * Shows empty grid when no threat data is available.
 */
import { useMemo } from "react";
import { Panel } from "./Panel";
import { C } from "./data";
import { useAllThreats } from "@/hooks/useAISS";

const PALETTE = ["rgba(255,255,255,0.05)", C.cyan, C.campaign, C.warning, C.critical];
const DAYS  = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const HOURS = Array.from({ length: 24 }, (_, i) => String(i).padStart(2, "0"));

export function Heatmap() {
  const { data: threats } = useAllThreats();

  // Build real grid from threat timestamps
  const realGrid = useMemo<number[] | null>(() => {
    if (!threats || threats.length === 0) return null;
    const grid = Array(7 * 24).fill(0);
    for (const t of threats) {
      try {
        const d = new Date(t.detected_at);
        const day  = d.getDay();
        const hour = d.getHours();
        const idx  = day * 24 + hour;
        const sevScore =
          t.severity === "critical" ? 4 :
          t.severity === "high"     ? 3 :
          t.severity === "medium"   ? 2 : 1;
        grid[idx] = Math.max(grid[idx] as number, sevScore);
      } catch { /* skip */ }
    }
    return grid;
  }, [threats]);

  // Empty grid when no data
  const emptyGrid = useMemo(() => Array(7 * 24).fill(0), []);
  const cells = realGrid ?? emptyGrid;
  const totalThreats = threats?.length ?? 0;
  const peakHour = useMemo(() => {
    const hours = Array(24).fill(0);
    for (const t of threats ?? []) {
      try {
        const h = new Date(t.detected_at).getHours();
        hours[h]++;
      } catch { /* skip */ }
    }
    return hours.indexOf(Math.max(...hours));
  }, [threats]);

  return (
    <Panel
      title="Threat Density — 7d × 24h"
      right={
        totalThreats > 0
          ? <span className="font-mono text-[0.6rem] text-muted-foreground">{totalThreats} threats mapped</span>
          : <span className="label-cap text-muted-foreground">awaiting threat data</span>
      }
      bodyClassName="flex flex-col justify-between gap-3"
    >
      {/* Hour labels */}
      <div className="grid grid-flow-col grid-rows-1 gap-[3px] pl-8" style={{ gridTemplateColumns: `repeat(24, 1fr)` }}>
        {HOURS.map((h, i) => (
          <span key={h} className="text-center font-mono text-[0.42rem] text-muted-foreground"
            style={{ color: i === peakHour && totalThreats > 0 ? C.warning : undefined }}>
            {i % 6 === 0 ? h : ""}
          </span>
        ))}
      </div>

      {/* Grid */}
      <div className="flex gap-[3px]">
        {/* Day labels */}
        <div className="flex flex-col gap-[3px] pr-1" style={{ width: 28 }}>
          {DAYS.map((d) => (
            <span key={d} className="flex-1 text-right font-mono text-[0.45rem] text-muted-foreground"
              style={{ display: "flex", alignItems: "center", justifyContent: "flex-end", minHeight: 12 }}>
              {d}
            </span>
          ))}
        </div>

        <div className="grid flex-1 grid-flow-col grid-rows-7 gap-[3px]">
          {cells.map((v, i) => {
            const day  = Math.floor(i / 24);
            const hour = i % 24;
            return (
              <span
                key={i}
                className="aspect-square rounded-[2px]"
                title={`${DAYS[day]} ${HOURS[hour]}:00 — level ${v}`}
                style={{
                  backgroundColor: v === 0 ? PALETTE[0] : PALETTE[v],
                  opacity: v === 0 ? 1 : 0.35 + v * 0.16,
                  transition: "background-color .4s ease",
                  minWidth: 8,
                  minHeight: 8,
                }}
              />
            );
          })}
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-2 font-mono text-[0.6rem] text-[#7C8C85]">
        <span>LOW</span>
        {PALETTE.map((p, i) => (
          <i key={i} className="size-2.5 rounded-[2px] not-italic" style={{ backgroundColor: p, opacity: 0.75 }} />
        ))}
        <span>CRITICAL</span>
        {totalThreats > 0 && (
          <span className="ml-auto text-[0.55rem]">peak: {HOURS[peakHour]}:00</span>
        )}
      </div>
    </Panel>
  );
}
