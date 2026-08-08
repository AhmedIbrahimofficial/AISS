import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export type ActionTone = "default" | "critical" | "warning" | "success" | "info";

const toneVar: Record<ActionTone, string> = {
  default: "var(--muted-foreground)",
  critical: "var(--critical)",
  warning: "var(--warning)",
  success: "var(--success)",
  info: "var(--cyan)",
};

// Human-readable descriptions for every known action
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
  "WHOIS Lookup":        "Run WHOIS query on the source IP/domain",
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
  "Open Configuration Wizard": "Run the AISS setup wizard to configure integrations and API keys",
  "Generate Token":      "Generate a connection token for a remote agent machine",
  "Scan Networks":       "Discover all hosts on configured network segments",
  "Refresh Topology":    "Reload the network topology map from live data",
  "Add Segment":         "Register a new network segment for monitoring",
  "Open Wizard to Add Keys": "Open the setup wizard to add LLM API keys",
  "Export":              "Export current chart data",
  "Drill down":          "Open detailed view for this data",
};

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

  // Tooltip text — use explicit description prop or look up from action name
  const tip = description ?? ACTION_DESCRIPTIONS[label];

  const tooltip = tip ? (
    <div className="pointer-events-none absolute bottom-full left-1/2 z-50 mb-2 -translate-x-1/2 w-max max-w-[220px] rounded-md border border-[var(--hairline)] bg-[#0d1a15] px-2.5 py-1.5 text-[0.65rem] text-muted-foreground opacity-0 shadow-xl transition-opacity group-hover:opacity-100">
      <p className="font-mono text-[0.6rem] font-semibold uppercase tracking-widest text-foreground mb-0.5">{label}</p>
      <p className="leading-relaxed">{tip}</p>
      <div className="absolute left-1/2 top-full -translate-x-1/2 border-4 border-transparent border-t-[var(--hairline)]" />
    </div>
  ) : null;

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
      onClick={() =>
        onClick
          ? onClick()
          : toast.success(`${label} dispatched`, {
              description: `Operator action queued on the AISS response bus · ${new Date()
                .toTimeString()
                .slice(0, 8)} UTC`,
            })
      }
    >
      {tooltip}
      {icon}
      {label}
    </button>
  );
}

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

/** Toolbar shown above charts: zoom / range / export / fullscreen / drilldown */
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
