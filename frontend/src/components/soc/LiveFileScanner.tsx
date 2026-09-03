/**
 * Live File Scanner
 * Shows real files from the host machine's user directories.
 * Flags risky extensions (.exe, .ps1, .bat, etc.)
 * Auto-refreshes every 30 seconds.
 */
import { useQuery } from "@tanstack/react-query";
import { getLiveFiles } from "@/lib/api";
import type { LiveFile } from "@/lib/api";
import { Panel } from "./Panel";
import { Badge } from "./ui";
import { C } from "./data";
import { useState } from "react";

function fmtSize(bytes: number) {
  if (bytes > 1_000_000) return (bytes / 1_000_000).toFixed(1) + " MB";
  if (bytes > 1_000)     return (bytes / 1_000).toFixed(0) + " KB";
  return bytes + " B";
}

function fmtDate(epoch: number) {
  return new Date(epoch * 1000).toLocaleDateString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

const EXT_COLOR: Record<string, string> = {
  ".exe": C.critical, ".bat": C.critical, ".ps1": C.warning,
  ".vbs": C.warning, ".cmd": C.warning, ".js": C.campaign,
  ".jar": C.campaign, ".scr": C.critical, ".hta": C.critical,
  ".lnk": C.warning, ".com": C.critical,
};

export function LiveFileScanner() {
  const { data, isLoading } = useQuery({
    queryKey: ["live-files"],
    queryFn: getLiveFiles,
    refetchInterval: 30_000,
    staleTime: 20_000,
  });

  const [tab, setTab] = useState<"all" | "risky">("all");
  const [search, setSearch] = useState("");

  const allFiles  = data?.files ?? [];
  const risky     = data?.suspicious ?? [];
  const source    = tab === "risky" ? risky : allFiles;
  const visible   = source.filter((f) =>
    !search || f.name.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <Panel
      title="File System Scanner"
      right={
        <div className="flex items-center gap-2">
          {(data?.suspicious_count ?? 0) > 0 && (
            <Badge tone="critical">{data!.suspicious_count} risky files</Badge>
          )}
          <Badge tone="info">{data?.total_found ?? "…"} scanned</Badge>
        </div>
      }
    >
      {/* Dirs scanned */}
      {data?.dirs_scanned && (
        <div className="mb-2 flex flex-wrap gap-1">
          {data.dirs_scanned.map((d) => (
            <span key={d} className="rounded border border-[var(--hairline)] px-1.5 py-0.5 font-mono text-[0.5rem] text-muted-foreground">
              {d.split(/[/\\]/).slice(-2).join("/")}
            </span>
          ))}
        </div>
      )}

      {/* Toolbar */}
      <div className="mb-2 flex gap-2">
        <input
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search filename…"
          className="flex-1 min-w-0 rounded-md border border-[var(--hairline)] bg-white/5 px-2.5 py-1 text-xs outline-none placeholder:text-muted-foreground focus:border-primary/50"
        />
        {["all", "risky"].map((t) => (
          <button
            key={t}
            onClick={() => setTab(t as "all" | "risky")}
            className={`rounded border px-2 py-1 font-mono text-[0.6rem] uppercase transition-colors ${
              tab === t
                ? "border-primary/40 bg-primary/12 text-primary"
                : "border-transparent text-muted-foreground hover:bg-white/5"
            }`}
          >
            {t === "risky" ? `⚠ ${risky.length} risky` : "all"}
          </button>
        ))}
      </div>

      {/* Table */}
      <div className="overflow-x-auto overflow-y-auto max-h-[300px] rounded-md border border-[var(--hairline)]">
        {isLoading ? (
          <div className="flex h-24 items-center justify-center">
            <div className="size-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          </div>
        ) : (
          <table className="w-full min-w-[540px] text-left">
            <thead className="sticky top-0 z-10 border-b border-[var(--hairline)] bg-[#0d1a15]">
              <tr>
                {["Name", "Ext", "Size", "Directory", "Modified", "Risk"].map((h) => (
                  <th key={h} className="label-cap px-2.5 py-2 font-medium text-[0.55rem]">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {visible.slice(0, 80).map((f: LiveFile, i) => {
                const extColor = EXT_COLOR[f.ext];
                return (
                  <tr
                    key={i}
                    className={`border-b border-[var(--hairline)] last:border-0 hover:bg-white/4 transition-colors ${
                      f.risk ? "bg-[rgba(220,38,38,0.03)]" : ""
                    }`}
                  >
                    <td className="px-2.5 py-1.5">
                      <span className="font-mono text-xs" title={f.path}>{f.name}</span>
                    </td>
                    <td className="px-2.5 py-1.5">
                      <span
                        className="font-mono text-[0.65rem] font-semibold"
                        style={{ color: extColor ?? C.muted }}
                      >
                        {f.ext || "—"}
                      </span>
                    </td>
                    <td className="px-2.5 py-1.5 font-mono text-[0.65rem] text-muted-foreground">
                      {fmtSize(f.size)}
                    </td>
                    <td className="px-2.5 py-1.5 max-w-[160px]">
                      <span className="truncate font-mono text-[0.55rem] text-muted-foreground block" title={f.dir}>
                        {f.dir.split(/[/\\]/).slice(-2).join("/")}
                      </span>
                    </td>
                    <td className="px-2.5 py-1.5 font-mono text-[0.6rem] text-muted-foreground whitespace-nowrap">
                      {fmtDate(f.modified)}
                    </td>
                    <td className="px-2.5 py-1.5">
                      {f.risk
                        ? <Badge tone="critical">RISKY</Badge>
                        : <Badge tone="success">SAFE</Badge>
                      }
                    </td>
                  </tr>
                );
              })}
              {visible.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-xs text-muted-foreground">
                    No files found
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>
      {visible.length > 80 && (
        <p className="mt-1 text-center text-[0.6rem] text-muted-foreground">
          Showing 80 of {visible.length}
        </p>
      )}
    </Panel>
  );
}
