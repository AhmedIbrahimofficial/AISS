import { useEffect, useState } from "react";
import { Panel } from "./Panel";
import { C } from "./data";

const PALETTE = ["rgba(255,255,255,0.05)", C.cyan, C.campaign, C.warning, C.critical];

function grid() {
  return Array.from({ length: 7 * 24 }, () => {
    const r = Math.random();
    return r > 0.94 ? 4 : r > 0.86 ? 3 : r > 0.7 ? 2 : r > 0.4 ? 1 : 0;
  });
}

export function Heatmap() {
  const [cells, setCells] = useState<number[]>(() => Array.from({ length: 7 * 24 }, () => 0));

  useEffect(() => {
    setCells(grid());
    const t = setInterval(() => {
      setCells((c) => {
        const next = [...c];
        for (let i = 0; i < 12; i++) {
          const idx = Math.floor(Math.random() * next.length);
          next[idx] = Math.floor(Math.random() * 5);
        }
        return next;
      });
    }, 1800);
    return () => clearInterval(t);
  }, []);

  return (
    <Panel title="Threat Density — 7d × 24h" bodyClassName="flex flex-col justify-between gap-3">
      <div className="grid grid-flow-col grid-rows-7 gap-[3px]">
        {cells.map((v, i) => (
          <span
            key={i}
            className="aspect-square rounded-[2px]"
            style={{
              backgroundColor: v === 0 ? PALETTE[0] : PALETTE[v],
              opacity: v === 0 ? 1 : 0.35 + v * 0.16,
              
              transition: "background-color .4s ease",
            }}
          />
        ))}
      </div>
      <div className="flex items-center gap-2 font-mono text-[0.6rem] text-[#7C8C85]">
        LOW
        {PALETTE.map((p, i) => (
          <i key={i} className="size-2.5 rounded-[2px]" style={{ backgroundColor: p, opacity: 0.75 }} />
        ))}
        CRITICAL
      </div>
    </Panel>
  );
}
