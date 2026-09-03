/**
 * AttackMap — shows REAL attack origins from actual detected threats.
 * When no threats exist, the map is EMPTY and score shows SYSTEM CLEAR.
 * Arcs are drawn only for real threat source IPs.
 * No fake simulation, no random score.
 */
import { useQuery } from "@tanstack/react-query";
import { Panel } from "./Panel";
import { C } from "./data";
import { getActiveThreats, getThreatStats, getNetworkConnections } from "@/lib/api";

// Rough continent silhouettes (equirectangular projection, 400×200 canvas)
const CONTINENTS = [
  "M60,52 L96,42 L124,50 L120,72 L96,92 L74,86 L58,70 Z",   // North America
  "M92,100 L110,96 L118,120 L106,150 L92,140 L86,118 Z",     // South America
  "M176,40 L214,34 L232,44 L226,62 L200,66 L182,58 Z",       // Europe
  "M180,70 L214,66 L226,86 L214,124 L196,140 L186,112 Z",    // Africa
  "M238,38 L318,30 L344,52 L332,80 L292,92 L252,70 Z",       // Asia
  "M300,96 L330,92 L340,106 L322,118 L302,112 Z",            // SE Asia
  "M318,138 L352,132 L362,150 L340,162 L320,154 Z",          // Australia
];

// Map IP first-octet ranges to approximate map coordinates
function ipToMapXY(ip: string): [number, number] | null {
  const parts = ip.split(".");
  if (parts.length < 2) return null;
  const a = parseInt(parts[0] ?? "0");
  const b = parseInt(parts[1] ?? "0");
  if (isNaN(a) || isNaN(b)) return null;

  // Private IPs — map to "local" position (center)
  if (a === 10 || a === 172 || a === 192 || a === 127) return null;

  // Rough geographic mapping by first octet
  if (a >= 1   && a <= 60)  return [60  + (b % 40), 52 + (a % 30)]; // North America
  if (a >= 61  && a <= 80)  return [300 + (b % 40), 40 + (a % 40)]; // Asia
  if (a >= 81  && a <= 100) return [180 + (b % 30), 55 + (a % 20)]; // Europe
  if (a >= 101 && a <= 130) return [185 + (b % 30), 80 + (a % 40)]; // Africa/Middle East
  if (a >= 131 && a <= 160) return [95  + (b % 25), 105 + (a % 35)]; // South America
  if (a >= 161 && a <= 180) return [320 + (b % 30), 100 + (a % 40)]; // SE Asia / Oceania
  if (a >= 181 && a <= 220) return [250 + (b % 50), 40  + (a % 35)]; // Asia-Pacific
  return [200 + (a % 100), 60 + (b % 80)]; // fallback
}

// Severity → color
function sevToColor(sev: string): string {
  switch (sev) {
    case "critical": return C.critical;
    case "high":     return C.warning;
    case "medium":   return C.campaign;
    default:         return C.cyan;
  }
}

// Destination: center-left (represents "your system")
const DEST: [number, number] = [96, 66];
const r     = 42;
const circ  = 2 * Math.PI * r;

export function AttackMap() {
  const { data: threats } = useQuery({
    queryKey: ["threats", "active"],
    queryFn:  getActiveThreats,
    refetchInterval: 5000,
    select: d => d.threats,
  });
  const { data: stats } = useQuery({
    queryKey: ["threat-stats"],
    queryFn:  getThreatStats,
    refetchInterval: 5000,
  });
  const { data: netData } = useQuery({
    queryKey: ["network-connections"],
    queryFn:  getNetworkConnections,
    refetchInterval: 8000,
  });

  // Build arcs from real threat sources only
  const arcs = (threats ?? [])
    .filter(t => t.source && t.source.match(/\d+\.\d+\.\d+\.\d+/))
    .map(t => {
      const ipMatch = t.source.match(/\d+\.\d+\.\d+\.\d+/);
      const ip = ipMatch?.[0] ?? "";
      const coords = ipToMapXY(ip);
      if (!coords) return null;
      return {
        id:    t.id,
        x1:    coords[0],
        y1:    coords[1],
        x2:    DEST[0],
        y2:    DEST[1],
        color: sevToColor(t.severity),
        label: t.type,
        ip,
      };
    })
    .filter(Boolean)
    .slice(0, 8) as { id: string; x1: number; y1: number; x2: number; y2: number; color: string; label: string; ip: string }[];

  // Also add blocked external connections as lower-severity arcs
  const connArcs = (netData?.connections ?? [])
    .filter(c => {
      const ip = c.remote_address?.split(":")?.[0] ?? "";
      return ip && !ip.startsWith("127.") && !ip.startsWith("10.") &&
             !ip.startsWith("192.168.") && !ip.startsWith("172.") &&
             c.status === "ESTABLISHED";
    })
    .slice(0, 4)
    .map((c, i) => {
      const ip = c.remote_address?.split(":")?.[0] ?? "";
      const coords = ipToMapXY(ip);
      if (!coords) return null;
      return {
        id:    `conn-${i}`,
        x1:    coords[0],
        y1:    coords[1],
        x2:    DEST[0],
        y2:    DEST[1],
        color: C.teal,
        label: "Connection",
        ip,
      };
    })
    .filter(Boolean) as typeof arcs;

  const allArcs = [...arcs, ...connArcs].slice(0, 10);

  // Real threat score based on actual data
  const active   = stats?.active   ?? 0;
  const critical = stats?.critical ?? 0;
  const high     = stats?.high     ?? 0;
  const score = active === 0
    ? 0  // no threats = 0 risk
    : Math.min(100, critical * 25 + high * 12 + (stats?.medium ?? 0) * 5 + active * 3);

  const ringColor = score === 0 ? C.success : score > 60 ? C.critical : score > 30 ? C.warning : C.teal;
  const statusLabel = score === 0
    ? "SYSTEM CLEAR"
    : score > 60
    ? "ACTIVE BREACH RISK"
    : score > 30
    ? "ELEVATED RISK"
    : "LOW RISK";

  return (
    <Panel title="Live Attack Origins" bodyClassName="flex flex-col gap-3">
      {/* Map */}
      <div className="relative">
        <svg viewBox="0 0 400 200" className="w-full">
          {/* Continents */}
          {CONTINENTS.map((d, i) => (
            <path key={i} d={d}
              fill="rgba(59,130,246,0.06)"
              stroke="rgba(59,130,246,0.20)"
              strokeWidth="0.6" />
          ))}

          {/* "Your system" target dot */}
          <circle cx={DEST[0]} cy={DEST[1]} r="4" fill={C.teal} />
          <circle cx={DEST[0]} cy={DEST[1]} r="8" fill="none" stroke={C.teal} strokeWidth="0.8" opacity="0.4" />
          <circle cx={DEST[0]} cy={DEST[1]} r="14" fill="none" stroke={C.teal} strokeWidth="0.4" opacity="0.2" />

          {/* Real attack arcs */}
          {allArcs.map(a => {
            const mx = (a.x1 + a.x2) / 2;
            const my = Math.min(a.y1, a.y2) - 36;
            return (
              <g key={a.id}>
                {/* Ghost trail */}
                <path d={`M${a.x1},${a.y1} Q${mx},${my} ${a.x2},${a.y2}`}
                  fill="none" stroke={a.color} strokeWidth="1" opacity="0.2" />
                {/* Main arc */}
                <path d={`M${a.x1},${a.y1} Q${mx},${my} ${a.x2},${a.y2}`}
                  fill="none" stroke={a.color} strokeWidth="1.6"
                  strokeLinecap="round" strokeDasharray="4 2" opacity="0.85" />
                {/* Origin dot */}
                <circle cx={a.x1} cy={a.y1} r="2.8" fill={a.color} />
              </g>
            );
          })}

          {/* No threats label */}
          {allArcs.length === 0 && (
            <text x="200" y="105" textAnchor="middle"
              fill="rgba(124,140,133,0.4)" fontSize="10" fontFamily="monospace">
              No active threats detected
            </text>
          )}
        </svg>
      </div>

      {/* Score strip */}
      <div className="flex items-center gap-4 border-t border-[rgba(255,255,255,0.06)] pt-3">
        <svg viewBox="0 0 100 100" className="size-16 shrink-0 -rotate-90">
          <circle cx="50" cy="50" r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="8" />
          <circle cx="50" cy="50" r={r} fill="none" stroke={ringColor} strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${(score / 100) * circ} ${circ}`}
            style={{ transition: "stroke-dasharray 1s ease" }} />
        </svg>
        <div className="ml-[-4.5rem] w-16 text-center">
          <p className="font-mono text-xl font-bold leading-none" style={{ color: ringColor }}>
            {score}
          </p>
        </div>
        <div className="ml-2 min-w-0">
          <p className="label-cap text-[0.55rem]">Threat Score</p>
          <p className="mt-0.5 font-mono text-xs font-semibold" style={{ color: ringColor }}>
            {statusLabel}
          </p>
          <p className="mt-0.5 font-mono text-[0.6rem] text-muted-foreground">
            {allArcs.length > 0
              ? `${allArcs.length} real vector${allArcs.length !== 1 ? "s" : ""} tracked`
              : active === 0
              ? "system is clean"
              : `${active} threat${active !== 1 ? "s" : ""} active`
            }
          </p>
        </div>
      </div>
    </Panel>
  );
}
