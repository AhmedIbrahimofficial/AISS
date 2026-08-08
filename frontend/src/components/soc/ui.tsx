import type { ReactNode } from "react";
import { Panel } from "./Panel";

export function Metric({
  label,
  value,
  sub,
  tone = "default",
}: {
  label: string;
  value: string;
  sub?: string;
  tone?: "default" | "critical" | "warning" | "success" | "info";
}) {
  const color = {
    default: "var(--foreground)",
    critical: "var(--critical)",
    warning: "var(--warning)",
    success: "var(--success)",
    info: "var(--cyan)",
  }[tone];
  return (
    <Panel className="p-4">
      <p className="label-cap">{label}</p>
      <p className="mt-2 font-mono text-2xl font-semibold" style={{ color }}>
        {value}
      </p>
      {sub && <p className="mt-1 text-xs text-muted-foreground">{sub}</p>}
    </Panel>
  );
}

export function Badge({ children, tone = "muted" }: { children: ReactNode; tone?: string }) {
  const map: Record<string, string> = {
    muted: "var(--muted-foreground)",
    critical: "var(--critical)",
    warning: "var(--warning)",
    success: "var(--success)",
    info: "var(--cyan)",
  };
  const c = map[tone] ?? map["muted"]!;
  return (
    <span
      className="rounded border px-2 py-0.5 font-mono text-[0.6rem] tracking-wider whitespace-nowrap"
      style={{
        color: c,
        borderColor: `color-mix(in oklab, ${c} 35%, transparent)`,
        background: `color-mix(in oklab, ${c} 10%, transparent)`,
      }}
    >
      {children}
    </span>
  );
}

export function DataTable({
  columns,
  rows,
}: {
  columns: string[];
  rows: (string | ReactNode)[][];
}) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[560px] text-left text-sm">
        <thead>
          <tr className="border-b border-[var(--hairline)]">
            {columns.map((c) => (
              <th key={c} className="label-cap px-3 py-2 font-medium">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r, i) => (
            <tr
              key={i}
              className="border-b border-[var(--hairline)] last:border-0 hover:bg-white/3"
            >
              {r.map((cell, j) => (
                <td key={j} className="px-3 py-2.5 align-middle whitespace-nowrap">
                  {cell}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function Bar({ value, tone = "var(--teal)" }: { value: number; tone?: string }) {
  return (
    <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
      <div
        className="h-full rounded-full"
        style={{ width: `${Math.min(100, value)}%`, background: tone }}
      />
    </div>
  );
}
