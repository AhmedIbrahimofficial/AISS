/**
 * Live Process Monitor
 * Shows every real running process on the host machine.
 * Suspicious processes are highlighted in red.
 * Auto-refreshes every 6 seconds.
 */
import { useQuery } from "@tanstack/react-query";
import { getLiveProcesses } from "@/lib/api";
import type { LiveProcess } from "@/lib/api";
import { Panel } from "./Panel";
import { Badge } from "./ui";
import { C } from "./data";
import { useState } from "react";

function fmtTime(epoch: number) {
  if (!epoch) return "--";
  return new Date(epoch * 1000).toTimeString().slice(0, 8);
}

function fmtSize(mb: number) {
  if (mb >= 1000) return (mb / 1024).toFixed(1) + " GB";
  return mb.toFixed(1) + " MB";
}

export function LiveProcessMonitor() {
  const { data, isLoading } = useQuery({
    queryKey: ["live-processes"],
    queryFn: getLiveProcesses,
    refetchInterval: 6000,
  });

  const [filter, setFilter] = useState<"all" | "suspicious">("all");
  const [search, setSearch] = useState("");

  const procs = data?.processes ?? [];
  const visible = procs.filter((p) => {
    if (filter === "suspicious" && !p.suspicious) return false;
    if (search && !p.name.toLowerCase().includes(search.toLowerCase()) &&
        !p.cmd.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  return (
    <Panel
      title="Live Processes"
      right={
        <div className="flex items-center gap-2">
          {data?.suspicious_count ? (
            <Badge tone="critical">{data.suspicious_count} suspicious</Badge>
          ) : null}
          <Badge tone="info">{data?.total ?? "…"} total</Badge>
          <span className="dot-pulse size-2 bg-[var(--success)] text-[var(--success)]" />
        </div>
      }
    >
      {/* Toolbar */}
      <div className="mb-2 flex gap-2">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search process name or command…"
          className="flex-1 min-w-0 rounded-md border border-[var(--hairline)] bg-white/5 px-2.5 py-1 text-xs outline-none placeholder:text-muted-foreground focus:border-primary/50"
        />
        {["all", "suspicious"].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f as "all" | "suspicious")}
            className={`rounded border px-2 py-1 font-mono text-[0.6rem] uppercase transition-colors ${
              filter === f
                ? "border-primary/40 bg-primary/12 text-primary"
                : "border-transparent text-muted-foreground hover:bg-white/5"
            }`}
          >
            {f}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="overflow-x-auto overflow-y-auto max-h-[340px] rounded-md border border-[var(--hairline)]">
        {isLoading ? (
          <div className="flex h-24 items-center justify-center">
            <div className="size-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          </div>
        ) : (
          <table className="w-full min-w-[640px] text-left">
            <thead className="sticky top-0 z-10 border-b border-[var(--hairline)] bg-[#0d1a15]">
              <tr>
                {["PID", "Name", "User", "CPU%", "RAM", "Status", "Started", "Risk"].map((h) => (
                  <th key={h} className="label-cap px-2.5 py-2 font-medium text-[0.55rem]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.slice(0, 60).map((p: LiveProcess) => (
                <tr
                  key={p.pid}
                  className={`border-b border-[var(--hairline)] last:border-0 transition-colors hover:bg-white/4 ${
                    p.suspicious ? "bg-[rgba(220,38,38,0.04)]" : ""
                  }`}
                >
                  <td className="px-2.5 py-1.5 font-mono text-[0.65rem] text-muted-foreground">{p.pid}</td>
                  <td className="px-2.5 py-1.5">
                    <div className="flex items-center gap-1.5">
                      {p.suspicious && (
                        <span className="size-1.5 rounded-full bg-[var(--critical)] dot-pulse" />
                      )}
                      <span className="font-mono text-xs">{p.name}</span>
                    </div>
                    {p.cmd && (
                      <p className="truncate font-mono text-[0.55rem] text-muted-foreground max-w-[200px]" title={p.cmd}>
                        {p.cmd}
                      </p>
                    )}
                  </td>
                  <td className="px-2.5 py-1.5 font-mono text-[0.65rem] text-muted-foreground">{p.user.split("\\").pop()}</td>
                  <td className="px-2.5 py-1.5">
                    <span className="font-mono text-xs" style={{
                      color: p.cpu > 50 ? C.critical : p.cpu > 20 ? C.warning : C.teal
                    }}>
                      {p.cpu.toFixed(1)}%
                    </span>
                  </td>
                  <td className="px-2.5 py-1.5 font-mono text-[0.65rem] text-muted-foreground">
                    {p.mem.toFixed(1)}%
                  </td>
                  <td className="px-2.5 py-1.5">
                    <Badge tone={p.status === "running" ? "success" : p.status === "sleeping" ? "default" : "warning"}>
                      {p.status}
                    </Badge>
                  </td>
                  <td className="px-2.5 py-1.5 font-mono text-[0.6rem] text-muted-foreground">{fmtTime(p.started)}</td>
                  <td className="px-2.5 py-1.5">
                    {p.suspicious
                      ? <Badge tone="critical">SUSPECT</Badge>
                      : <Badge tone="success">OK</Badge>
                    }
                  </td>
                </tr>
              ))}
              {visible.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-6 text-center text-xs text-muted-foreground">
                    No processes match filter
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
      {visible.length > 60 && (
        <p className="mt-1 text-center text-[0.6rem] text-muted-foreground">
          Showing 60 of {visible.length} — use search to narrow
        </p>
      )}
    </Panel>
  );
}
