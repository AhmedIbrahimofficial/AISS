/**
 * Packet Activity Visualizer
 * Animates bars based on real network stats.
 * Shows flatline when no real throughput data is available.
 */
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Panel } from "./Panel";
import { getNetworkStats } from "@/lib/api";

const BARS = 44;

export function PacketVisualizer() {
  const { data: netStats } = useQuery({
    queryKey: ["network-stats"],
    queryFn: getNetworkStats,
    refetchInterval: 4000,
  });

  const [bars, setBars] = useState<number[]>(() => Array.from({ length: BARS }, () => 0.05));

  useEffect(() => {
    // When we have real throughput, normalise it (assume max ~50 MB/s for display)
    const base = netStats
      ? Math.min(1, (netStats.throughput_mb ?? 0) / 50)
      : 0;

    if (base === 0) {
      // No real data — show flatline
      setBars(Array.from({ length: BARS }, () => 0.05));
      return;
    }

    const t = setInterval(() => {
      setBars((b) =>
        b.map((v) =>
          Math.max(0.05, Math.min(1, base + (Math.random() - 0.5) * 0.3 + (v - base) * 0.7)),
        ),
      );
    }, 200);
    return () => clearInterval(t);
  }, [netStats]);

  const throughputLabel = netStats
    ? `${netStats.throughput_mb.toFixed(1)} MB/s`
    : "live";

  const blockedLabel = netStats && netStats.blocked > 0
    ? `${netStats.blocked} blocked`
    : undefined;

  return (
    <Panel
      title="Packet Activity"
      right={
        <div className="flex items-center gap-2">
          {blockedLabel && (
            <span className="font-mono text-[0.58rem] text-[var(--critical)]">{blockedLabel}</span>
          )}
          <span className="label-cap">{throughputLabel}</span>
        </div>
      }
    >
      <div className="flex h-[120px] items-end gap-[3px]">
        {bars.map((v, i) => (
          <span
            key={i}
            className="flex-1 rounded-sm"
            style={{
              height: `${v * 100}%`,
              background:
                v > 0.8
                  ? "linear-gradient(to top, #DC2626, #F97316)"
                  : v > 0.6
                    ? "linear-gradient(to top, #D97706, #0EA5E9)"
                    : "linear-gradient(to top, #0EA5E9, #3B82F6)",
              transition: "height .2s ease",
            }}
          />
        ))}
      </div>
      {netStats && (
        <div className="mt-2 grid grid-cols-3 gap-2 text-center">
          <div>
            <p className="font-mono text-sm">{netStats.connections}</p>
            <p className="label-cap text-[0.5rem]">connections</p>
          </div>
          <div>
            <p className="font-mono text-sm text-[var(--critical)]">{netStats.blocked}</p>
            <p className="label-cap text-[0.5rem]">blocked</p>
          </div>
          <div>
            <p className="font-mono text-sm">{netStats.throughput_mb.toFixed(1)}</p>
            <p className="label-cap text-[0.5rem]">MB/s</p>
          </div>
        </div>
      )}
    </Panel>
  );
}
