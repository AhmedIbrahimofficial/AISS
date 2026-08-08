import { useEffect, useState } from "react";
import { Panel } from "./Panel";
import { C, timeLabel } from "./data";

const ACTIONS = [
  { label: "IP 45.83.12.77 blackholed", color: C.critical },
  { label: "SSH session terminated", color: C.warning },
  { label: "Host EPA-412 quarantined", color: C.campaign },
  { label: "Signature set 8.42 pushed", color: C.cyan },
  { label: "Ransomware process killed", color: C.critical },
  { label: "Firewall rule auto-committed", color: C.success },
];

type Item = { id: number; label: string; color: string; time: string };

let seq = 0;
export function AutoResponseTimeline() {
  const [items, setItems] = useState<Item[]>([]);

  useEffect(() => {
    const make = (): Item => {
      const a = ACTIONS[Math.floor(Math.random() * ACTIONS.length)]!;
      return { id: seq++, label: a.label, color: a.color, time: timeLabel(new Date()) };
    };
    setItems(Array.from({ length: 5 }, make));
    const t = setInterval(() => setItems((i) => [...i.slice(-5), make()]), 5000);
    return () => clearInterval(t);
  }, []);

  return (
    <Panel title="Auto-Response Timeline" bodyClassName="overflow-x-auto">
      <div className="relative min-w-[520px] pt-6">
        <div className="absolute left-0 right-0 top-8 h-px bg-[linear-gradient(90deg,transparent,rgba(59,130,246,0.5),transparent)]" />
        <div className="flex justify-between gap-4">
          {items.map((it) => (
            <div key={it.id} className="flex-1 text-center">
              <span
                className="mx-auto block size-2.5 rounded-full"
                style={{ backgroundColor: it.color }}
              />
              <p className="mt-3 font-mono text-[0.6rem] text-[#7C8C85]">{it.time}</p>
              <p className="mt-1 text-[0.68rem] leading-snug text-[#E6EDEA]">{it.label}</p>
            </div>
          ))}
        </div>
      </div>
      <div className="mt-auto grid grid-cols-2 gap-2 pt-4 sm:grid-cols-4">
        {[
          ["Actions / hour", "146"],
          ["Autonomous rate", "92%"],
          ["Analyst overrides", "4"],
          ["Rollback events", "0"],
        ].map(([k, v]) => (
          <div key={k} className="rounded-md border border-[var(--hairline)] bg-white/3 px-3 py-2">
            <p className="label-cap truncate text-[0.55rem]">{k}</p>
            <p className="mt-1 font-mono text-base">{v}</p>
          </div>
        ))}
      </div>
    </Panel>
  );
}
