/**
 * Kill Chain Visualization
 * Maps real detected threats → MITRE kill chain stages.
 * Data from /api/kill-chain  (returns stages[], total_threats, attack_progress)
 */
import { useQuery } from "@tanstack/react-query";
import { getKillChain } from "@/lib/api";
import { Panel } from "./Panel";
import { Badge } from "./ui";

const FALLBACK_STAGES = [
  { id: "reconnaissance",     label: "Recon",     icon: "🔍", color: "#6366f1", compromised: false, total: 0, active: 0 },
  { id: "initial_access",     label: "Access",    icon: "🚪", color: "#f59e0b", compromised: false, total: 0, active: 0 },
  { id: "execution",          label: "Exec",      icon: "⚡", color: "#ef4444", compromised: false, total: 0, active: 0 },
  { id: "privilege_escalation",label: "Priv-Esc", icon: "🔓", color: "#dc2626", compromised: false, total: 0, active: 0 },
  { id: "defense_evasion",    label: "Evasion",   icon: "🥷", color: "#7c3aed", compromised: false, total: 0, active: 0 },
  { id: "lateral_movement",   label: "Lateral",   icon: "↔",  color: "#0891b2", compromised: false, total: 0, active: 0 },
  { id: "command_control",    label: "C2",        icon: "📡", color: "#059669", compromised: false, total: 0, active: 0 },
  { id: "exfiltration",       label: "Exfil",     icon: "💀", color: "#ff0000", compromised: false, total: 0, active: 0 },
];

export function KillChain() {
  const { data, isError } = useQuery({
    queryKey: ["kill-chain"],
    queryFn:  getKillChain,
    refetchInterval: 10_000,
    retry: 2,
  });

  const stages      = data?.stages ?? FALLBACK_STAGES;
  const compromised = data?.stages_compromised ?? 0;
  const progress    = data?.attack_progress    ?? 0;
  const total       = data?.total_threats      ?? 0;

  return (
    <Panel
      title="Kill Chain Monitor"
      right={
        compromised > 0
          ? <Badge tone="critical">{compromised} stages compromised</Badge>
          : <Badge tone="success">clear</Badge>
      }
    >
      {/* Progress bar */}
      {total > 0 && (
        <div className="mb-3 flex items-center gap-2">
          <div className="flex-1 h-1 rounded-full bg-white/5 overflow-hidden">
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${progress}%`,
                background: progress > 60 ? "#ef4444" : progress > 30 ? "#f59e0b" : "#10b981",
              }}
            />
          </div>
          <span className="font-mono text-[0.6rem] text-muted-foreground shrink-0">{progress}% progression</span>
        </div>
      )}

      {/* Stage chevrons */}
      <div className="flex items-stretch gap-0.5 overflow-x-auto pb-1">
        {stages.map((s, i) => {
          const active = s.compromised;
          const color  = s.color ?? "#6366f1";
          return (
            <div key={s.id} className="flex flex-col items-center gap-1 flex-1 min-w-0">
              {/* Connector */}
              {i > 0 && (
                <div
                  className="h-px w-full mb-0.5"
                  style={{ background: active ? `${color}60` : "rgba(255,255,255,0.06)" }}
                />
              )}
              <div
                className="relative w-full rounded px-1 py-2 text-center transition-all duration-300"
                style={{
                  background: active
                    ? `color-mix(in oklch, ${color} 18%, transparent)`
                    : "rgba(255,255,255,0.03)",
                  border: `1px solid ${active ? color : "rgba(255,255,255,0.07)"}`,
                  boxShadow: active ? `0 0 10px ${color}40, inset 0 0 6px ${color}12` : "none",
                }}
              >
                {active && (
                  <span
                    className="absolute inset-0 rounded animate-pulse"
                    style={{ background: `${color}10`, animationDuration: "1.8s" }}
                  />
                )}
                <div
                  className="relative font-mono text-[0.48rem] font-bold tracking-wider leading-tight"
                  style={{ color: active ? color : "rgba(124,140,133,0.5)" }}
                >
                  <div className="text-[0.7rem] mb-0.5">{s.icon}</div>
                  <div>{s.label.toUpperCase()}</div>
                  {s.total > 0 && (
                    <div
                      className="mt-0.5 rounded text-[0.42rem] px-1 mx-auto w-fit"
                      style={{ background: `${color}30`, color }}
                    >
                      {s.total}
                    </div>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Threat list under active stages */}
      {total > 0 ? (
        <ul className="mt-3 space-y-1 border-t border-[var(--hairline)] pt-2">
          {stages
            .filter((s) => s.compromised && s.total > 0)
            .flatMap((s) =>
              (s.threats ?? []).slice(0, 2).map((t) => ({
                ...t,
                _stageColor: s.color,
                _stageLabel: s.label,
              }))
            )
            .slice(0, 6)
            .map((t) => (
              <li key={t.id} className="grid grid-cols-[auto_minmax(0,1fr)_auto_auto] items-center gap-2">
                <span
                  className="size-1.5 rounded-full shrink-0"
                  style={{ background: t._stageColor }}
                />
                <span className="truncate font-mono text-[0.62rem]">{t.source || t.type}</span>
                <span
                  className="font-mono text-[0.5rem] shrink-0"
                  style={{ color: t._stageColor }}
                >
                  {t._stageLabel.toUpperCase()}
                </span>
                <Badge
                  tone={
                    t.severity === "critical" ? "critical"
                    : t.severity === "high"    ? "warning"
                    : "info"
                  }
                >
                  {t.severity}
                </Badge>
              </li>
            ))}
        </ul>
      ) : (
        <p className="mt-2 text-center text-[0.65rem] text-muted-foreground border-t border-[var(--hairline)] pt-2">
          {isError ? "Could not reach backend — no live data" : "No active kill chains detected"}
        </p>
      )}
    </Panel>
  );
}
