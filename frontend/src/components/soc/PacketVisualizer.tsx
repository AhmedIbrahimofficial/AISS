import { useEffect, useState } from "react";
import { Panel } from "./Panel";

const BARS = 44;

export function PacketVisualizer() {
  const [bars, setBars] = useState<number[]>(() => Array.from({ length: BARS }, () => 0.3));

  useEffect(() => {
    const t = setInterval(() => {
      setBars((b) => b.map((v) => Math.max(0.08, Math.min(1, v + (Math.random() - 0.5) * 0.7))));
    }, 220);
    return () => clearInterval(t);
  }, []);

  return (
    <Panel title="Packet Activity" right={<span className="label-cap">14.2 Gb/s</span>}>
      <div className="flex h-[120px] items-end gap-[3px]">
        {bars.map((v, i) => (
          <span
            key={i}
            className="flex-1 rounded-sm"
            style={{
              height: `${v * 100}%`,
              background: "linear-gradient(to top, #0EA5E9, #3B82F6)",
              
              transition: "height .2s ease",
            }}
          />
        ))}
      </div>
    </Panel>
  );
}
