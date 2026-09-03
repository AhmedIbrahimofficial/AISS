/**
 * LiveScannerFeed — sci-fi streaming feed of real system events
 *
 * Continuously polls the backend for processes, files, network connections
 * and "announces" new findings one-by-one with a typewriter/teletype effect.
 * Feels like a live scanning terminal.
 */
import { useEffect, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getLiveProcesses, getLiveFiles, getLiveNetworkStats, getLiveDisk } from "@/lib/api";
import { Panel } from "./Panel";
import { Badge } from "./ui";
import { C } from "./data";

type EventSeverity = "info" | "warn" | "alert" | "ok";

interface ScanEvent {
  id: string;
  time: string;
  type: string;
  msg: string;
  severity: EventSeverity;
  source: string;
}

const SEV_COLOR: Record<EventSeverity, string> = {
  alert: C.critical,
  warn:  C.warning,
  info:  C.cyan,
  ok:    C.success,
};

const SEV_LABEL: Record<EventSeverity, string> = {
  alert: "ALERT",
  warn:  "WARN",
  info:  "INFO",
  ok:    "OK",
};

function now() {
  return new Date().toTimeString().slice(0, 8);
}

function uid() {
  return Math.random().toString(36).slice(2, 9);
}

/** Typewriter span — characters appear one-by-one */
function TypeMsg({ text, color }: { text: string; color: string }) {
  const [displayed, setDisplayed] = useState("");
  const idx = useRef(0);

  useEffect(() => {
    idx.current = 0;
    setDisplayed("");
    const interval = setInterval(() => {
      idx.current++;
      setDisplayed(text.slice(0, idx.current));
      if (idx.current >= text.length) clearInterval(interval);
    }, 14);
    return () => clearInterval(interval);
  }, [text]);

  return (
    <span style={{ color }} className="font-mono text-xs">
      {displayed}
      {displayed.length < text.length && (
        <span className="ml-0.5 inline-block h-3 w-1.5 animate-pulse bg-current opacity-80" />
      )}
    </span>
  );
}

export function LiveScannerFeed() {
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const seenProcs = useRef(new Set<number>());
  const seenFiles = useRef(new Set<string>());
  const prevConns = useRef(0);
  const prevCpu   = useRef(0);
  const prevDisk  = useRef<Record<string, number>>({});
  const bottomRef = useRef<HTMLDivElement>(null);

  const push = (ev: Omit<ScanEvent, "id" | "time">) => {
    setEvents((prev) => [
      { ...ev, id: uid(), time: now() },
      ...prev.slice(0, 149),
    ]);
  };

  // ── Live processes ─────────────────────────────────────────────────
  const { data: procs } = useQuery({
    queryKey: ["live-processes"],
    queryFn: getLiveProcesses,
    refetchInterval: 5000,
  });

  useEffect(() => {
    if (!procs) return;
    for (const p of procs.processes) {
      if (!seenProcs.current.has(p.pid)) {
        seenProcs.current.add(p.pid);
        if (p.suspicious) {
          push({
            type: "PROC/SUSPECT",
            msg: `Suspicious process detected: ${p.name} (PID ${p.pid}) — ${p.cmd.slice(0, 60) || p.exe.split(/[/\\]/).pop() || "?"}`,
            severity: "alert",
            source: "ProcessScanner",
          });
        } else if (p.cpu > 40) {
          push({
            type: "PROC/HIGH-CPU",
            msg: `High CPU process: ${p.name} (PID ${p.pid}) — ${p.cpu.toFixed(1)}% CPU`,
            severity: "warn",
            source: "ProcessScanner",
          });
        }
      }
    }
  }, [procs]);

  // ── Live files ─────────────────────────────────────────────────────
  const { data: files } = useQuery({
    queryKey: ["live-files"],
    queryFn: getLiveFiles,
    refetchInterval: 20_000,
    staleTime: 15_000,
  });

  useEffect(() => {
    if (!files) return;
    // Announce risky files first
    for (const f of files.suspicious) {
      const key = f.path;
      if (!seenFiles.current.has(key)) {
        seenFiles.current.add(key);
        push({
          type: "FILE/RISKY",
          msg: `Risky file detected: ${f.name} [${f.ext}] in ${f.dir.split(/[/\\]/).slice(-2).join("/")}`,
          severity: "alert",
          source: "FileScanner",
        });
      }
    }
    // Announce any new non-risky files that showed up
    for (const f of files.files.slice(0, 5)) {
      const key = f.path;
      if (!seenFiles.current.has(key)) {
        seenFiles.current.add(key);
        push({
          type: "FILE/SCANNED",
          msg: `Scanned: ${f.name} [${f.ext || "no-ext"}] ${(f.size / 1024).toFixed(1)} KB`,
          severity: "info",
          source: "FileScanner",
        });
      }
    }
  }, [files]);

  // ── Network stats ──────────────────────────────────────────────────
  const { data: net } = useQuery({
    queryKey: ["live-network-stats"],
    queryFn: getLiveNetworkStats,
    refetchInterval: 4000,
  });

  useEffect(() => {
    if (!net) return;
    const delta = net.connections - prevConns.current;
    if (prevConns.current > 0 && delta >= 10) {
      push({
        type: "NET/SPIKE",
        msg: `Connection spike: ${net.connections} active (+${delta} new), ${net.blocked} blocked`,
        severity: "warn",
        source: "NetworkMonitor",
      });
    }
    if (net.recv_mb_s > 5) {
      push({
        type: "NET/TRAFFIC",
        msg: `High inbound traffic: ${net.recv_mb_s.toFixed(2)} MB/s recv, ${net.sent_mb_s.toFixed(2)} MB/s sent`,
        severity: "warn",
        source: "NetworkMonitor",
      });
    }
    prevConns.current = net.connections;
  }, [net]);

  // ── Disk ───────────────────────────────────────────────────────────
  const { data: disk } = useQuery({
    queryKey: ["live-disk"],
    queryFn: getLiveDisk,
    refetchInterval: 30_000,
  });

  useEffect(() => {
    if (!disk) return;
    for (const p of disk.partitions) {
      const prev = prevDisk.current[p.mountpoint];
      if (p.percent >= 90 && (prev === undefined || prev < 90)) {
        push({
          type: "DISK/CRITICAL",
          msg: `Disk almost full: ${p.mountpoint} ${p.percent}% used (${p.free_gb} GB free)`,
          severity: "alert",
          source: "DiskMonitor",
        });
      } else if (p.percent >= 75 && (prev === undefined || prev < 75)) {
        push({
          type: "DISK/WARN",
          msg: `Disk usage high: ${p.mountpoint} ${p.percent}% used`,
          severity: "warn",
          source: "DiskMonitor",
        });
      }
      prevDisk.current[p.mountpoint] = p.percent;
    }
  }, [disk]);

  // ── Initial scan announcement ──────────────────────────────────────
  useEffect(() => {
    push({ type: "SCAN/INIT", msg: "AISS live scanner active — monitoring processes, files, network, disk", severity: "ok", source: "Scanner" });
    push({ type: "SCAN/INIT", msg: "Baseline established — watching for anomalies and new activity", severity: "info", source: "Scanner" });
  }, []);

  // ── Periodic heartbeat ─────────────────────────────────────────────
  useEffect(() => {
    const t = setInterval(() => {
      const p = procs?.total ?? 0;
      const c = net?.connections ?? 0;
      const s = procs?.suspicious_count ?? 0;
      push({
        type: "SYS/HEARTBEAT",
        msg: `Heartbeat: ${p} processes · ${c} connections · ${s > 0 ? `${s} suspicious` : "no threats"}`,
        severity: s > 0 ? "warn" : "ok",
        source: "Monitor",
      });
    }, 30_000);
    return () => clearInterval(t);
  }, [procs, net]);

  return (
    <Panel
      title="⬤ LIVE SCANNER FEED"
      right={
        <div className="flex items-center gap-2">
          <span className="dot-pulse size-2 bg-[var(--success)] text-[var(--success)]" />
          <Badge tone="success">scanning</Badge>
        </div>
      }
      bodyClassName="p-0"
    >
      {/* Terminal-style header */}
      <div className="border-b border-[var(--hairline)] bg-black/30 px-3 py-1.5">
        <div className="flex items-center gap-2">
          <span className="font-mono text-[0.6rem] text-[var(--success)]">AISS</span>
          <span className="font-mono text-[0.6rem] text-muted-foreground">scanner@localhost:~$</span>
          <span className="animate-pulse text-[0.6rem] text-[var(--success)]">_</span>
        </div>
      </div>

      {/* Event stream */}
      <div className="max-h-[420px] overflow-y-auto font-mono">
        {events.map((ev, i) => {
          const color = SEV_COLOR[ev.severity];
          return (
            <div
              key={ev.id}
              className={`flex gap-2 border-b border-[rgba(255,255,255,0.04)] px-3 py-1 text-[0.65rem] transition-all ${
                i === 0 ? "bg-white/4" : ""
              }`}
            >
              {/* Timestamp */}
              <span className="shrink-0 text-muted-foreground opacity-50">{ev.time}</span>

              {/* Severity badge */}
              <span
                className="shrink-0 rounded px-1 font-bold"
                style={{
                  color,
                  background: `color-mix(in oklab, ${color} 12%, transparent)`,
                }}
              >
                {SEV_LABEL[ev.severity]}
              </span>

              {/* Type tag */}
              <span className="shrink-0 text-muted-foreground opacity-60">[{ev.type}]</span>

              {/* Message — typewriter on new item */}
              <span className="min-w-0 flex-1">
                {i === 0 ? (
                  <TypeMsg text={ev.msg} color={color} />
                ) : (
                  <span style={{ color: ev.severity === "alert" ? color : undefined }}>{ev.msg}</span>
                )}
              </span>

              {/* Source */}
              <span className="shrink-0 text-muted-foreground opacity-40">{ev.source}</span>
            </div>
          );
        })}
        <div ref={bottomRef} />
      </div>

      {/* Summary strip */}
      <div className="flex items-center justify-between border-t border-[var(--hairline)] bg-black/20 px-3 py-1.5">
        <div className="flex items-center gap-4 font-mono text-[0.58rem] text-muted-foreground">
          <span>{procs?.total ?? "—"} processes</span>
          <span>{files?.total_found ?? "—"} files</span>
          <span>{net?.connections ?? "—"} connections</span>
        </div>
        <span className="font-mono text-[0.58rem] text-muted-foreground">{events.length} events</span>
      </div>
    </Panel>
  );
}
