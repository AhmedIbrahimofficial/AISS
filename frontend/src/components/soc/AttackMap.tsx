import { useEffect, useState } from "react";
import { Panel } from "./Panel";
import { C } from "./data";

// Rough stylized continent silhouettes on a 400x200 equirectangular-ish canvas.
const CONTINENTS = [
  "M60,52 L96,42 L124,50 L120,72 L96,92 L74,86 L58,70 Z",
  "M92,100 L110,96 L118,120 L106,150 L92,140 L86,118 Z",
  "M176,40 L214,34 L232,44 L226,62 L200,66 L182,58 Z",
  "M180,70 L214,66 L226,86 L214,124 L196,140 L186,112 Z",
  "M238,38 L318,30 L344,52 L332,80 L292,92 L252,70 Z",
  "M300,96 L330,92 L340,106 L322,118 L302,112 Z",
  "M318,138 L352,132 L362,150 L340,162 L320,154 Z",
];

type Arc = { id: number; x1: number; y1: number; x2: number; y2: number; color: string };

const ORIGINS = [
  [72, 62],
  [206, 50],
  [300, 58],
  [104, 122],
  [332, 148],
  [196, 110],
];
const DEST: [number, number] = [96, 66];
const COLORS = [C.cyan, C.campaign, C.warning, C.critical];

export function AttackMap() {
  const [arcs, setArcs] = useState<Arc[]>([]);
  const [score, setScore] = useState(94);

  useEffect(() => {
    let id = 0;
    const push = () => {
      const o = ORIGINS[Math.floor(Math.random() * ORIGINS.length)]!;
      const color = COLORS[Math.floor(Math.random() * COLORS.length)]!;
      const arc: Arc = { id: id++, x1: o[0]!, y1: o[1]!, x2: DEST[0], y2: DEST[1], color };
      setArcs((a) => [...a.slice(-5), arc]);
      setScore(() => 78 + Math.floor(Math.random() * 20));
    };
    push();
    const t = setInterval(push, 2200);
    return () => clearInterval(t);
  }, []);

  const ringColor = score > 90 ? C.success : score > 82 ? C.warning : C.critical;
  const r = 42;
  const circ = 2 * Math.PI * r;

  return (
    <Panel title="Live Attack Origins" bodyClassName="flex flex-col gap-4">
      <svg viewBox="0 0 400 200" className="w-full">
        {CONTINENTS.map((d, i) => (
          <path key={i} d={d} fill="rgba(59,130,246,0.07)" stroke="rgba(59,130,246,0.25)" strokeWidth="0.6" />
        ))}
        {arcs.map((a) => {
          const mx = (a.x1 + a.x2) / 2;
          const my = Math.min(a.y1, a.y2) - 48;
          return (
            <g key={a.id}>
              <path
                d={`M${a.x1},${a.y1} Q${mx},${my} ${a.x2},${a.y2}`}
                fill="none"
                stroke={a.color}
                strokeWidth="1.2"
                opacity="0.35"
              />
              <path
                className="arc-flow"
                d={`M${a.x1},${a.y1} Q${mx},${my} ${a.x2},${a.y2}`}
                fill="none"
                stroke={a.color}
                strokeWidth="1.8"
                strokeLinecap="round"
                
              />
              <circle cx={a.x1} cy={a.y1} r="2.6" fill={a.color}  />
            </g>
          );
        })}
        <circle cx={DEST[0]} cy={DEST[1]} r="3.4" fill={C.teal}  />
      </svg>

      <div className="flex items-center gap-5 border-t border-[rgba(255,255,255,0.06)] pt-4">
        <svg viewBox="0 0 100 100" className="size-24 -rotate-90">
          <circle cx="50" cy="50" r={r} fill="none" stroke="rgba(255,255,255,0.07)" strokeWidth="8" />
          <circle
            cx="50"
            cy="50"
            r={r}
            fill="none"
            stroke={ringColor}
            strokeWidth="8"
            strokeLinecap="round"
            strokeDasharray={`${(score / 100) * circ} ${circ}`}
            style={{ transition: "stroke-dasharray .8s ease" }}
          />
        </svg>
        <div className="-ml-[6.1rem] w-24 text-center">
          <p className="font-mono text-2xl font-bold" style={{ color: ringColor }}>
            {score}
          </p>
        </div>
        <div className="ml-4">
          <p className="label-cap">Threat Score</p>
          <p className="mt-1 font-mono text-xs text-[#E6EDEA]">
            {score > 90 ? "POSTURE STABLE" : score > 82 ? "ELEVATED RISK" : "ACTIVE BREACH RISK"}
          </p>
          <p className="mt-1 font-mono text-[0.65rem] text-[#7C8C85]">{arcs.length} live vectors tracked</p>
        </div>
      </div>
    </Panel>
  );
}
