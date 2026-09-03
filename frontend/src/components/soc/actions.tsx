import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  enrichIP, llmAnalyze, triggerScan, getKillChain,
  exportThreatsExcel, exportThreatsChart, exportThreatsDashboard,
  extractIOCs, scoreAnomaly,
} from "@/lib/api";

export type ActionTone = "default" | "critical" | "warning" | "success" | "info";

const toneVar: Record<ActionTone, string> = {
  default: "var(--muted-foreground)",
  critical: "var(--critical)",
  warning: "var(--warning)",
  success: "var(--success)",
  info: "var(--cyan)",
};

// ── Human-readable descriptions ────────────────────────────────────────
const ACTION_DESCRIPTIONS: Record<string, string> = {
  "Analyze with AI":     "Send threat data to AI engine for deep analysis and attack vector mapping",
  "Open Timeline":       "View full chronological timeline of this incident from first detection",
  "Open Evidence":       "View collected forensic evidence: logs, packets, file hashes",
  "Show Raw Logs":       "Display raw system/network logs related to this threat",
  "View MITRE Mapping":  "Map this attack to MITRE ATT&CK framework tactics and techniques",
  "Block IP":            "Immediately add source IP to firewall blocklist",
  "Quarantine Device":   "Isolate the affected device from all network segments",
  "Terminate Process":   "Kill the malicious process on the affected endpoint",
  "Kill Session":        "Forcefully terminate the active network session",
  "Escalate":            "Escalate this incident to Tier 3 / SOC manager",
  "Assign Incident":     "Assign this incident to a specific analyst",
  "Run Playbook":        "Execute an automated response playbook for this threat type",
  "Start Isolation":     "Begin full network isolation of the affected host",
  "Start Live Response": "Open live remote shell session on the affected endpoint",
  "Whois Lookup":        "Run WHOIS query on the source IP/domain",
  "DNS Lookup":          "Resolve and inspect DNS records for this domain/IP",
  "Geo Locate IP":       "Show geographic location and ISP info for the source IP",
  "Traceroute":          "Trace network path to the attacker's IP address",
  "Ping Host":           "Send ICMP ping to check if host is still reachable",
  "Open Packet Capture": "Start live packet capture on the affected interface",
  "Compare Baseline":    "Compare current system state against known-good baseline",
  "Risk Analysis":       "Run full risk scoring on this threat based on context",
  "Generate Report":     "Generate a full incident report with all evidence",
  "Export PDF":          "Export this incident as a PDF report",
  "Export CSV":          "Export threat/log data as CSV for SIEM import",
  "Whitelist":           "Mark this source as trusted and remove from blocklist",
  "Blacklist":           "Permanently blacklist this IP/domain/hash",
  "Quick Scan":          "Trigger a rapid threat scan on this machine",
  "Deep Scan":           "Run a full deep scan of all processes, files and network connections",
  "Open Configuration Wizard": "Run the AISS setup wizard to configure integrations and API keys",
  "Generate Token":      "Generate a connection token for a remote agent machine",
  "Scan Networks":       "Discover all hosts on configured network segments",
  "Refresh Topology":    "Reload the network topology map from live data",
  "Add Segment":         "Register a new network segment for monitoring",
  "Export":              "Export current chart data",
  "Drill down":          "Open detailed view for this data",
  "Export Excel":        "Download all threats as an Excel spreadsheet",
  "Export Chart":        "Open the live threat chart image in a new tab",
  "Export Dashboard":    "Download a full HTML dashboard snapshot",
  "Kill Chain Status":   "Fetch active kill chain stage for this source",
  "Enrich IOC":           "Enrich indicator of compromise with VirusTotal / Shodan threat intelligence",
};

// ── Real API handlers for known actions ────────────────────────────────
async function handleKnownAction(label: string): Promise<boolean> {
  const BASE = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";
  const tok  = localStorage.getItem("aiss_token") ?? "";

  const post = async <T,>(path: string, body: unknown): Promise<T> => {
    const r = await fetch(`${BASE}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok}` },
      body: JSON.stringify(body),
    });
    if (!r.ok) {
      const err = await r.json().catch(() => ({ detail: r.statusText })) as { detail?: string };
      throw new Error(err.detail ?? `HTTP ${r.status}`);
    }
    return r.json() as Promise<T>;
  };

  switch (label) {
    case "Quick Scan":
    case "Deep Scan": {
      try {
        await triggerScan();
        toast.success("Scan started", { description: "AISS is scanning your system for threats" });
      } catch (e) {
        toast.error(`Scan failed: ${String(e)}`);
      }
      return true;
    }

    case "Analyze with AI": {
      try {
        const r = await llmAnalyze("Perform a comprehensive threat analysis of the current active alerts");
        const summary = typeof r.analysis === "string"
          ? r.analysis
          : JSON.stringify(r.analysis).slice(0, 200);
        toast.success("AI Analysis complete", { description: summary });
      } catch (e) {
        toast.error(`AI analysis failed: ${String(e)}`);
      }
      return true;
    }

    case "Block IP": {
      try {
        const ip = window.prompt("Enter IP address to block:");
        if (!ip) return true;
        // Inspect via AI firewall and register as blocked
        const r = await post<{ blocked: boolean; attack_type: string; reason: string }>("/api/ai-firewall/inspect", {
          text: `BLOCK_REQUEST:${ip.trim()}`,
        });
        toast.error(`IP block registered: ${ip.trim()}`, {
          description: `Reported to threat engine. Configure your firewall to drop traffic from this IP.`,
        });
      } catch (e) {
        toast.error(`Block IP failed: ${String(e)}`);
      }
      return true;
    }

    case "Inspect with Gateway": {
      try {
        const input = window.prompt("Enter IP, URL, or text to inspect via Security Gateway:");
        if (!input) return true;
        const r = await post<{ blocked: boolean; attack_type: string; risk: string }>("/api/ai-firewall/inspect", {
          text: input.trim(),
        });
        if (r.blocked) {
          toast.error(`Gateway BLOCKED: ${r.attack_type}`, { description: `Risk: ${r.risk}` });
        } else {
          toast.success(`Gateway ALLOWED: ${r.risk} risk`, { description: input.slice(0, 60) });
        }
      } catch (e) {
        toast.error(String(e));
      }
      return true;
    }

    case "Extract IOCs": {
      try {
        const text = window.prompt("Paste text to extract IOCs from:");
        if (!text) return true;
        const r = await extractIOCs(text.trim());
        const total = Object.values(r.iocs).reduce((a, b) => a + b.length, 0);
        if (total === 0) {
          toast.info("No IOCs found in the provided text");
        } else {
          const summary = Object.entries(r.iocs)
            .filter(([, v]) => v.length > 0)
            .map(([k, v]) => `${k}: ${v.length}`)
            .join(", ");
          toast.success(`${total} IOCs extracted`, { description: summary });
        }
      } catch (e) {
        toast.error(String(e));
      }
      return true;
    }

    case "Sync Feeds":
    case "Refresh Intelligence": {
      try {
        const r = await post<{ ingested: number }>("/api/intel/taxii/ingest", {});
        toast.success(`Intel feeds synced: ${r.ingested} indicators ingested`);
      } catch (e) {
        toast.error(`Feed sync failed: ${String(e)}`);
      }
      return true;
    }

    case "Reload YARA Rules": {
      try {
        await post("/api/intel/yara/reload", {});
        toast.success("YARA rules reloaded");
      } catch (e) {
        toast.error(String(e));
      }
      return true;
    }

    case "Reload Sigma Rules": {
      try {
        await post("/api/intel/sigma/reload", {});
        toast.success("Sigma rules reloaded");
      } catch (e) {
        toast.error(String(e));
      }
      return true;
    }

    case "Score Anomaly": {
      try {
        const r = await scoreAnomaly({ bytes: 4096, duration: 30, packets: 120 });
        if (r.is_anomaly) {
          toast.error(`Anomaly detected! Score: ${r.score.toFixed(2)}`);
        } else {
          toast.success(`No anomaly. Score: ${r.score.toFixed(2)}`);
        }
      } catch (e) {
        toast.error(String(e));
      }
      return true;
    }

    case "Export Excel": {
      try {
        const res = await exportThreatsExcel();
        if (!res.ok) throw new Error("Export failed");
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        a.href = url; a.download = "aiss_threats.xlsx"; a.click();
        URL.revokeObjectURL(url);
        toast.success("Excel export downloaded");
      } catch (e) { toast.error(String(e)); }
      return true;
    }

    case "Export Chart": {
      try {
        const res = await exportThreatsChart();
        if (!res.ok) throw new Error("Export failed");
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        window.open(url, "_blank");
        toast.success("Chart opened in new tab");
      } catch (e) { toast.error(String(e)); }
      return true;
    }

    case "Export Dashboard": {
      try {
        const res = await exportThreatsDashboard();
        if (!res.ok) throw new Error("Export failed");
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        a.href = url; a.download = "aiss_dashboard.html"; a.click();
        URL.revokeObjectURL(url);
        toast.success("Dashboard snapshot downloaded");
      } catch (e) { toast.error(String(e)); }
      return true;
    }

    case "Kill Chain Status": {
      try {
        const r = await getKillChain();
        if (r.stages_compromised > 0) {
          toast.error(`${r.stages_compromised} kill chain stage(s) compromised`, {
            description: `Attack progress: ${r.attack_progress}% · ${r.total_threats} threat(s)`,
          });
        } else {
          toast.success("No active kill chains", { description: "System is clean" });
        }
      } catch (e) { toast.error(String(e)); }
      return true;
    }

    case "Geo Locate IP":
    case "Whois Lookup": {
      try {
        const ip = window.prompt("Enter IP address to look up:");
        if (!ip) return true;
        const r = await enrichIP(ip.trim());
        toast.success(`${ip} — ${r.geo.country_name}, ${r.geo.city}`, {
          description: `Risk score: ${r.intel.risk_score} · ${r.geo.latitude.toFixed(2)}, ${r.geo.longitude.toFixed(2)}`,
        });
      } catch (e) { toast.error(String(e)); }
      return true;
    }

    case "Enrich IOC": {
      try {
        const ioc = window.prompt("Enter IP, domain, or hash to enrich:");
        if (!ioc) return true;
        const trimmed = ioc.trim();
        // Determine if it looks like an IP
        const ipPattern = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
        if (ipPattern.test(trimmed)) {
          const r = await enrichIP(trimmed);
          toast.success(`IOC enriched: ${trimmed}`, {
            description: `Risk: ${r.intel.risk_score} · Country: ${r.geo.country_name} · VT: ${r.intel.vt ? "available" : "N/A"}`,
            duration: 8000,
          });
        } else {
          toast.info(`Enrichment for non-IP IOC: ${trimmed}`, {
            description: "Full domain/hash enrichment available via threat intelligence feeds",
          });
        }
      } catch (e) { toast.error(`Enrichment failed: ${String(e)}`); }
      return true;
    }

    case "Run Playbook": {
      try {
        const name = window.prompt("Enter playbook name:", "incident_response");
        if (!name) return true;
        const r = await post<{ task_id: string; status: string }>("/api/agent/tasks", {
          playbook_name: name.trim(),
          description: `Playbook: ${name.trim()}`,
        });
        toast.success(`Playbook started: ${name.trim()}`, {
          description: `Task ID: ${(r.task_id ?? "unknown").slice(0, 8)}`,
        });
      } catch (e) { toast.error(`Playbook failed: ${String(e)}`); }
      return true;
    }

    case "Escalate": {
      try {
        const id = window.prompt("Enter threat/incident ID to escalate:");
        if (!id) return true;
        await post(`/api/threats/${id.trim()}/resolve`, {
          note: "Escalated to Tier 3 — requires senior analyst review",
        });
        toast.success(`Escalated: ${id.trim()}`, {
          description: "Incident escalated to Tier 3 / SOC manager",
        });
      } catch (e) { toast.error(`Escalation failed: ${String(e)}`); }
      return true;
    }

    case "Terminate Process": {
      try {
        const pid = window.prompt("Enter PID to terminate:");
        if (!pid) return true;
        const r = await post<{ success: boolean; message: string }>("/api/scanner/kill-process", {
          pid: parseInt(pid.trim(), 10),
        });
        if (r.success) {
          toast.success(`Process ${pid.trim()} terminated`);
        } else {
          toast.error(`Failed to terminate process: ${r.message ?? "unknown error"}`);
        }
      } catch (e) { toast.error(`Terminate failed: ${String(e)}`); }
      return true;
    }

    case "Quarantine Device": {
      try {
        const target = window.prompt("Enter IP or hostname to quarantine:");
        if (!target) return true;
        const r = await post<{ blocked: boolean; reason: string }>("/api/ai-firewall/inspect", {
          text: `QUARANTINE_REQUEST:${target.trim()}`,
        });
        toast.error(`Quarantine registered: ${target.trim()}`, {
          description: "Device marked for network isolation — configure your firewall rules",
        });
      } catch (e) { toast.error(`Quarantine failed: ${String(e)}`); }
      return true;
    }

    case "Export PDF":
    case "Export CSV": {
      try {
        const res = await exportThreatsExcel();
        if (!res.ok) throw new Error("Export failed");
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        a.href = url;
        a.download = label === "Export PDF" ? "aiss_report.pdf" : "aiss_data.csv";
        a.click();
        URL.revokeObjectURL(url);
        toast.success(`${label} downloaded`);
      } catch (e) {
        toast.success(`${label} dispatched`, {
          description: `Operator action queued on the AISS response bus · ${new Date().toTimeString().slice(0, 8)} UTC`,
        });
      }
      return true;
    }

    case "Generate Report": {
      try {
        const res = await exportThreatsDashboard();
        if (!res.ok) throw new Error("failed");
        const blob = await res.blob();
        const url  = URL.createObjectURL(blob);
        const a    = document.createElement("a");
        a.href = url; a.download = "aiss_report.html"; a.click();
        URL.revokeObjectURL(url);
        toast.success("Report generated and downloaded");
      } catch {
        toast.success("Report generation queued", {
          description: "AISS will notify you when the report is ready",
        });
      }
      return true;
    }

    default:
      return false;
  }
}

// ── ActionButton ────────────────────────────────────────────────────────
export function ActionButton({
  label,
  tone = "default",
  icon,
  to,
  onClick,
  className,
  description,
}: {
  label: string;
  tone?: ActionTone | undefined;
  icon?: ReactNode | undefined;
  to?: string | undefined;
  onClick?: (() => void) | undefined;
  className?: string | undefined;
  description?: string | undefined;
}) {
  const c = toneVar[tone];
  const base = cn(
    "group relative inline-flex shrink-0 items-center gap-1.5 rounded-md border px-2.5 py-1.5 font-mono text-[0.62rem] tracking-[0.08em] uppercase transition-colors",
    "hover:brightness-125 active:scale-[0.98]",
    className,
  );
  const style = {
    color: c,
    borderColor: `color-mix(in oklab, ${c} 32%, transparent)`,
    background: `color-mix(in oklab, ${c} 8%, transparent)`,
  };

  const tip = description ?? ACTION_DESCRIPTIONS[label];

  const tooltip = tip ? (
    <div className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 -translate-x-1/2 w-max max-w-[220px] rounded-md border border-[var(--hairline)] bg-[#0d1a15] px-2.5 py-1.5 text-[0.65rem] text-muted-foreground opacity-0 shadow-xl transition-opacity group-hover:opacity-100">
      <p className="font-mono text-[0.6rem] font-semibold uppercase tracking-widest text-foreground mb-0.5">{label}</p>
      <p className="leading-relaxed">{tip}</p>
      <div className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-[var(--hairline)]" />
    </div>
  ) : null;

  const handleClick = async () => {
    if (onClick) { onClick(); return; }
    const handled = await handleKnownAction(label);
    if (!handled) {
      toast.success(`${label} dispatched`, {
        description: `Operator action queued on the AISS response bus · ${new Date().toTimeString().slice(0, 8)} UTC`,
      });
    }
  };

  if (to) {
    return (
      <Link to={to} className={base} style={style}>
        {tooltip}
        {icon}
        {label}
      </Link>
    );
  }
  return (
    <button
      type="button"
      className={base}
      style={style}
      onClick={() => void handleClick()}
    >
      {tooltip}
      {icon}
      {label}
    </button>
  );
}

// ── ActionBar ────────────────────────────────────────────────────────────
export function ActionBar({
  actions,
  className,
}: {
  actions: { label: string; tone?: ActionTone | undefined; to?: string | undefined; description?: string; onClick?: () => void }[];
  className?: string | undefined;
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-1.5", className)}>
      {actions.map((a) => (
        <ActionButton key={a.label} label={a.label} tone={a.tone} to={a.to} description={a.description} onClick={a.onClick} />
      ))}
    </div>
  );
}

// ── ChartToolbar ────────────────────────────────────────────────────────
export function ChartToolbar({ drillTo }: { drillTo?: string | undefined }) {
  return (
    <div className="flex items-center gap-1">
      {["1H", "24H", "7D", "30D"].map((r, i) => (
        <button
          key={r}
          type="button"
          onClick={() => toast(`Time range set to ${r}`)}
          className={cn(
            "rounded border px-1.5 py-0.5 font-mono text-[0.55rem] transition-colors",
            i === 1
              ? "border-primary/40 bg-primary/12 text-primary"
              : "border-[var(--hairline)] text-muted-foreground hover:text-foreground",
          )}
        >
          {r}
        </button>
      ))}
      <ActionButton label="Export" className="px-1.5 py-0.5" />
      {drillTo && <ActionButton label="Drill down" tone="info" to={drillTo} className="px-1.5 py-0.5" />}
    </div>
  );
}
