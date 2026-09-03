/**
 * Force-directed network topology graph.
 * Uses a simple spring-repulsion simulation (no D3 dependency).
 * Renders nodes as SVG circles colour-coded by type/status,
 * edges as lines, and animates toward equilibrium every frame.
 */
import { useEffect, useRef, useState, useCallback } from "react";
import { Panel } from "./Panel";
import { Badge } from "./ui";
import { C } from "./data";
import type { TopologyNode, TopologyEdge } from "@/lib/api";

// ── Types ──────────────────────────────────────────────────────────────
interface SimNode extends TopologyNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

// ── Colours per node type ──────────────────────────────────────────────
const TYPE_COLOR: Record<string, string> = {
  gateway:  C.teal,
  server:   C.cyan,
  endpoint: "#6366f1",
  sensor:   C.campaign,
  agent:    C.success,
  firewall: C.critical,
  router:   C.warning,
  cloud:    "#8B5CF6",
  unknown:  C.muted,
};

function nodeColor(n: TopologyNode) {
  if (n.status === "offline" || n.status === "down")  return "rgba(220,38,38,0.5)";
  if (n.status === "degraded")                         return C.warning;
  return TYPE_COLOR[n.type] ?? C.muted;
}

function nodeRadius(n: TopologyNode) {
  if (n.is_center) return 18;
  const t = n.type;
  if (t === "gateway" || t === "router" || t === "firewall") return 12;
  if (t === "server")   return 10;
  return 8;
}

// ── Spring simulation ──────────────────────────────────────────────────
const REPEL  = 3200;
const SPRING = 0.04;
const DAMP   = 0.82;
const IDEAL  = 110;

function step(nodes: SimNode[], edges: TopologyEdge[], w: number, h: number) {
  const cx = w / 2, cy = h / 2;

  // Repulsion
  for (let i = 0; i < nodes.length; i++) {
    const a = nodes[i]!;
    // Gravity toward centre
    a.vx += (cx - a.x) * 0.004;
    a.vy += (cy - a.y) * 0.004;

    for (let j = i + 1; j < nodes.length; j++) {
      const b = nodes[j]!;
      const dx = a.x - b.x, dy = a.y - b.y;
      const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const force = REPEL / (dist * dist);
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;
      a.vx += fx; a.vy += fy;
      b.vx -= fx; b.vy -= fy;
    }
  }

  // Spring attraction along edges
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  for (const e of edges) {
    const a = nodeMap.get(e.source), b = nodeMap.get(e.target);
    if (!a || !b) continue;
    const dx = b.x - a.x, dy = b.y - a.y;
    const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
    const diff = (dist - IDEAL) * SPRING;
    const fx = (dx / dist) * diff;
    const fy = (dy / dist) * diff;
    a.vx += fx; a.vy += fy;
    b.vx -= fx; b.vy -= fy;
  }

  // Integrate
  for (const n of nodes) {
    n.vx *= DAMP; n.vy *= DAMP;
    n.x += n.vx; n.y += n.vy;
    // Boundary clamp
    n.x = Math.max(20, Math.min(w - 20, n.x));
    n.y = Math.max(20, Math.min(h - 20, n.y));
  }
}

// ── Component ─────────────────────────────────────────────────────────
export function TopologyGraph({
  nodes: rawNodes,
  edges,
}: {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
}) {
  const svgRef  = useRef<SVGSVGElement>(null);
  const [nodes, setNodes]    = useState<SimNode[]>([]);
  const [selected, setSelected] = useState<SimNode | null>(null);
  const rafRef  = useRef<number>(0);
  const simRef  = useRef<SimNode[]>([]);
  const W = 680, H = 380;

  // Initialise simulation nodes with random positions
  useEffect(() => {
    const cx = W / 2, cy = H / 2;
    const sim: SimNode[] = rawNodes.map((n, i) => ({
      ...n,
      x: n.is_center ? cx : cx + Math.cos((i / rawNodes.length) * Math.PI * 2) * 140,
      y: n.is_center ? cy : cy + Math.sin((i / rawNodes.length) * Math.PI * 2) * 120,
      vx: (Math.random() - 0.5) * 2,
      vy: (Math.random() - 0.5) * 2,
    }));
    simRef.current = sim;
    setNodes([...sim]);
  }, [rawNodes]);

  // Animation loop — runs for 300 ticks then stops
  useEffect(() => {
    let tick = 0;
    const loop = () => {
      if (tick++ > 300) return;
      step(simRef.current, edges, W, H);
      setNodes([...simRef.current]);
      rafRef.current = requestAnimationFrame(loop);
    };
    rafRef.current = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(rafRef.current);
  }, [edges]);

  // Drag support
  const dragging = useRef<string | null>(null);

  const onMouseMove = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    if (!dragging.current || !svgRef.current) return;
    const rect = svgRef.current.getBoundingClientRect();
    const sx = ((e.clientX - rect.left) / rect.width)  * W;
    const sy = ((e.clientY - rect.top)  / rect.height) * H;
    const n = simRef.current.find((x) => x.id === dragging.current);
    if (!n) return;
    n.x = sx; n.y = sy; n.vx = 0; n.vy = 0;
    setNodes([...simRef.current]);
  }, []);

  const onMouseUp = useCallback(() => { dragging.current = null; }, []);

  if (rawNodes.length === 0) {
    return (
      <Panel title="Network Topology" right={<Badge tone="warning">no data</Badge>}>
        <div className="flex h-40 items-center justify-center text-sm text-muted-foreground">
          No topology data — run a network scan to populate
        </div>
      </Panel>
    );
  }

  return (
    <Panel
      title="Network Topology"
      right={
        <div className="flex items-center gap-3 text-[0.6rem] font-mono text-muted-foreground">
          {Object.entries(TYPE_COLOR).slice(0, 5).map(([type, color]) => (
            <span key={type} className="flex items-center gap-1">
              <span className="inline-block size-2 rounded-full" style={{ background: color }} />
              {type}
            </span>
          ))}
        </div>
      }
    >
      <svg
        ref={svgRef}
        viewBox={`0 0 ${W} ${H}`}
        className="w-full rounded-lg"
        style={{ background: "rgba(0,0,0,0.35)", cursor: "crosshair" }}
        onMouseMove={onMouseMove}
        onMouseUp={onMouseUp}
        onMouseLeave={onMouseUp}
      >
        <defs>
          <filter id="glow">
            <feGaussianBlur stdDeviation="2.5" result="coloredBlur" />
            <feMerge>
              <feMergeNode in="coloredBlur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5"
            markerWidth="5" markerHeight="5" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="rgba(59,130,246,0.4)" />
          </marker>
        </defs>

        {/* Edges */}
        {edges.map((e, i) => {
          const a = nodes.find((n) => n.id === e.source);
          const b = nodes.find((n) => n.id === e.target);
          if (!a || !b) return null;
          return (
            <g key={i}>
              <line
                x1={a.x} y1={a.y} x2={b.x} y2={b.y}
                stroke="rgba(59,130,246,0.15)"
                strokeWidth="1"
                markerEnd="url(#arrow)"
              />
              {e.label && (
                <text
                  x={(a.x + b.x) / 2}
                  y={(a.y + b.y) / 2 - 4}
                  textAnchor="middle"
                  fontSize="7"
                  fill="rgba(124,140,133,0.8)"
                >
                  {e.label}
                </text>
              )}
            </g>
          );
        })}

        {/* Nodes */}
        {nodes.map((n) => {
          const r     = nodeRadius(n);
          const color = nodeColor(n);
          const sel   = selected?.id === n.id;
          return (
            <g
              key={n.id}
              transform={`translate(${n.x},${n.y})`}
              style={{ cursor: "grab" }}
              onMouseDown={(e) => { e.preventDefault(); dragging.current = n.id; }}
              onClick={() => setSelected(sel ? null : n)}
            >
              {/* Pulse ring for threats / critical */}
              {n.status === "degraded" || n.status === "threat" ? (
                <circle r={r + 6} fill="none" stroke={C.critical} strokeWidth="1"
                  opacity="0.4" className="animate-ping" style={{ animationDuration: "2s" }} />
              ) : null}

              {/* Selection ring */}
              {sel && <circle r={r + 5} fill="none" stroke="#fff" strokeWidth="1.5" opacity="0.6" />}

              {/* Node body */}
              <circle r={r} fill={color} fillOpacity={0.9} filter="url(#glow)" />

              {/* Icon letter */}
              <text
                textAnchor="middle"
                dominantBaseline="central"
                fontSize={r < 10 ? "7" : "9"}
                fill="#fff"
                fontFamily="monospace"
                fontWeight="bold"
              >
                {n.type === "gateway"  ? "GW"
                  : n.type === "server"  ? "SV"
                  : n.type === "firewall"? "FW"
                  : n.type === "router"  ? "RT"
                  : n.type === "agent"   ? "AG"
                  : n.type === "sensor"  ? "SS"
                  : n.type === "cloud"   ? "CL"
                  : n.label.slice(0, 2).toUpperCase()}
              </text>

              {/* Label below node */}
              <text
                y={r + 10}
                textAnchor="middle"
                fontSize="8"
                fill="rgba(230,237,234,0.75)"
                fontFamily="monospace"
              >
                {n.label.length > 14 ? n.label.slice(0, 14) + "…" : n.label}
              </text>
              {n.ip && (
                <text y={r + 20} textAnchor="middle" fontSize="7" fill="rgba(124,140,133,0.7)" fontFamily="monospace">
                  {n.ip}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* Selected node detail */}
      {selected && (
        <div className="mt-2 rounded-md border border-[var(--hairline)] bg-white/3 px-3 py-2">
          <div className="flex items-center justify-between gap-4">
            <div className="min-w-0">
              <p className="truncate text-xs font-semibold">{selected.label}</p>
              <p className="font-mono text-[0.65rem] text-muted-foreground">
                {selected.type} · {selected.ip ?? "no IP"} · {selected.status}
              </p>
              {selected.net_type && (
                <p className="text-[0.6rem] text-muted-foreground">network: {selected.net_type}</p>
              )}
            </div>
            <Badge tone={selected.status === "online" ? "success" : selected.status === "degraded" ? "warning" : "critical"}>
              {selected.status}
            </Badge>
          </div>
        </div>
      )}
    </Panel>
  );
}
