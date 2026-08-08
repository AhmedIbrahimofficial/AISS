import { Panel } from "./Panel";
import { sevColor } from "./data";
import { useThreats } from "@/hooks/useAISS";
import type { Threat } from "@/lib/api";

function sevLabel(s: string) {
  return s.toUpperCase() as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
}

function timeLabel(iso: string) {
  try {
    return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return "--:--";
  }
}

export function ThreatFeed() {
  const { data: threats, isLoading } = useThreats();

  return (
    <Panel
      title="Live Threat Feed"
      right={<span className="dot-pulse size-2 bg-[#DC2626] text-[#DC2626]" />}
      bodyClassName="max-h-[280px] overflow-y-auto pr-1"
    >
      {isLoading && (
        <p className="text-xs text-muted-foreground py-4 text-center">Connecting to backend...</p>
      )}
      {!isLoading && (!threats || threats.length === 0) && (
        <p className="text-xs text-muted-foreground py-4 text-center">No active threats — system clear ✓</p>
      )}
      <ul className="space-y-1.5">
        {threats?.map((t: Threat) => {
          const sev = sevLabel(t.severity);
          const color = sevColor[sev] ?? "#888";
          return (
            <li key={t.id}
              className="animate-fade-in flex items-center gap-3 rounded-md border border-transparent px-2 py-1.5 transition-colors hover:border-[rgba(59,130,246,0.2)] hover:bg-[rgba(59,130,246,0.04)]"
            >
              <span
                className={`size-2 shrink-0 rounded-full ${sev === "CRITICAL" ? "dot-pulse" : ""}`}
                style={{ backgroundColor: color, color }}
              />
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs text-[#E6EDEA]">{t.type}</p>
                <p className="font-mono text-[0.65rem] text-[#7C8C85]">
                  {t.source} · {t.module}
                </p>
              </div>
              <span className="font-mono text-[0.55rem] tracking-widest" style={{ color }}>{sev}</span>
              <span className="font-mono text-[0.6rem] text-[#7C8C85]">{timeLabel(t.detected_at)}</span>
            </li>
          );
        })}
      </ul>
    </Panel>
  );
}
