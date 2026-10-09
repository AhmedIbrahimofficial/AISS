/**
 * ApprovalModal — human-in-the-loop approval gate for HIGH/CRITICAL operations
 * Redesigned to match AISS design system and make approval feel like a serious
 * security decision, not a random dialog.
 */
import { useEffect, useRef, useState } from "react";
import {
  AlertTriangle, Clock, CheckCircle2, XCircle,
  Shield, FileText, Zap, Lock,
} from "lucide-react";
import type { ApprovalRequest } from "../../api/agentApi";

interface ApprovalModalProps {
  approval: ApprovalRequest | null;
  onApprove: (id: string) => void;
  onReject:  (id: string) => void;
}

// What will happen — step list based on tool name
const IMPACT_STEPS: Record<string, string[]> = {
  quarantine_file:      ["File will be suspended", "Moved to encrypted quarantine", "Original location cleared", "Hash logged to audit trail"],
  kill_process:         ["Process will be suspended", "Forensic evidence collected", "Child processes identified", "Process tree terminated"],
  block_ip:             ["IP blocked via Windows Firewall", "Inbound + outbound rules added", "24-hour auto-expiry set", "Audit entry created"],
  terminate_process:    ["Process suspended immediately", "Open file handles closed", "Memory snapshot captured", "Process killed"],
  emergency_ransomware: ["Shadow copy deletion killed", "Affected processes terminated", "Admin alert sent", "Incident record created"],
};

function getImpactSteps(toolName: string): string[] {
  const key = Object.keys(IMPACT_STEPS).find(k => toolName.toLowerCase().includes(k));
  return key ? IMPACT_STEPS[key]! : [
    "Operation will execute immediately",
    "Changes will be logged in audit trail",
    "Action can be reviewed in Investigations",
  ];
}

export function ApprovalModal({ approval, onApprove, onReject }: ApprovalModalProps) {
  const [secondsLeft, setSecondsLeft] = useState(3600);
  const [isActing,    setIsActing]    = useState(false);
  const [expired,     setExpired]     = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const approveRef  = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!approval) return;
    setSecondsLeft(3600);
    setExpired(false);
    setIsActing(false);
    setTimeout(() => approveRef.current?.focus(), 100);

    intervalRef.current = setInterval(() => {
      setSecondsLeft(s => {
        if (s <= 1) { clearInterval(intervalRef.current!); setExpired(true); return 0; }
        return s - 1;
      });
    }, 1000);
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [approval?.id]);

  if (!approval) return null;

  const isCritical = approval.risk_level === "CRITICAL";
  const color      = isCritical ? "var(--critical)" : "#f97316";
  const colorBg    = isCritical ? "rgba(220,38,38,0.08)" : "rgba(249,115,22,0.08)";
  const colorBorder= isCritical ? "rgba(220,38,38,0.3)"  : "rgba(249,115,22,0.3)";

  const formatTime = (secs: number) =>
    `${Math.floor(secs / 60)}:${String(secs % 60).padStart(2, "0")}`;

  const impactSteps = getImpactSteps(approval.tool_name);

  const handleApprove = () => {
    if (isActing || expired) return;
    setIsActing(true);
    try { onApprove(approval.id); } finally { setIsActing(false); }
  };

  const handleReject = () => {
    if (isActing) return;
    setIsActing(true);
    try { onReject(approval.id); } finally { setIsActing(false); }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby="approval-title"
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/70 backdrop-blur-sm" />

      {/* Modal */}
      <div
        className="relative w-full max-w-md rounded-2xl border shadow-2xl overflow-hidden"
        style={{ borderColor: colorBorder, background: "#0a1410" }}
      >
        {/* Top accent bar */}
        <div className="h-0.5 w-full" style={{ background: `linear-gradient(90deg, ${color}, transparent)` }} />

        {/* Header */}
        <div className="flex items-start gap-3 px-5 pt-5 pb-4 border-b border-[var(--hairline)]"
          style={{ background: colorBg }}>
          <div className="flex size-10 shrink-0 items-center justify-center rounded-xl border"
            style={{ borderColor: colorBorder, background: `${color}15` }}>
            {isCritical
              ? <Lock className="size-5" style={{ color }} />
              : <AlertTriangle className="size-5" style={{ color }} />}
          </div>
          <div className="flex-1 min-w-0">
            <p className="font-mono text-[0.65rem] font-bold tracking-widest uppercase"
              style={{ color }}>
              {isCritical ? "⚠ CRITICAL ACTION — REQUIRES APPROVAL" : "⚠ HIGH RISK ACTION — REQUIRES APPROVAL"}
            </p>
            <h2 id="approval-title" className="mt-0.5 text-base font-semibold text-foreground">
              {approval.tool_name.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase())}
            </h2>
          </div>
          <span
            className="shrink-0 rounded-md border px-2 py-0.5 font-mono text-[0.62rem] font-bold"
            style={{ color, borderColor: colorBorder }}>
            {approval.risk_level}
          </span>
        </div>

        <div className="px-5 py-4 space-y-4">
          {/* Reason */}
          <div>
            <p className="label-cap text-[0.6rem] mb-1.5">AI detected</p>
            <p className="text-sm text-foreground leading-relaxed">{approval.description}</p>
          </div>

          {/* Why needed */}
          <div>
            <p className="label-cap text-[0.6rem] mb-1.5">Why this action</p>
            <p className="text-[0.78rem] text-muted-foreground leading-relaxed">{approval.reason}</p>
          </div>

          {/* Affected resource */}
          {approval.affected_resource && (
            <div className="flex items-start gap-2 rounded-lg border border-[var(--hairline)] bg-white/3 px-3 py-2.5">
              <Shield className="size-3.5 shrink-0 mt-0.5 text-muted-foreground" />
              <div>
                <p className="text-[0.6rem] text-muted-foreground mb-0.5 label-cap">Affected resource</p>
                <p className="font-mono text-xs">{approval.affected_resource}</p>
              </div>
            </div>
          )}

          {/* What will happen */}
          <div className="rounded-xl border px-4 py-3" style={{ borderColor: colorBorder, background: colorBg }}>
            <p className="label-cap text-[0.6rem] mb-2.5" style={{ color }}>What will happen</p>
            <div className="space-y-1.5">
              {impactSteps.map((step, i) => (
                <div key={i} className="flex items-center gap-2">
                  <CheckCircle2 className="size-3.5 shrink-0" style={{ color }} />
                  <span className="text-[0.78rem] text-foreground">{step}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Countdown */}
          <div className={`flex items-center gap-2 rounded-lg px-3 py-2 text-xs ${
            expired
              ? "border border-[var(--critical)]/30 bg-[var(--critical)]/8 text-[var(--critical)]"
              : secondsLeft < 300
              ? "border border-[var(--warning)]/30 bg-[var(--warning)]/8 text-[var(--warning)]"
              : "border border-[var(--hairline)] bg-white/3 text-muted-foreground"
          }`}>
            <Clock className="size-3.5 shrink-0" />
            {expired
              ? "Approval window has expired — operation cancelled"
              : <span>Auto-expires in <span className="font-mono font-bold text-foreground ml-1">{formatTime(secondsLeft)}</span></span>
            }
          </div>
        </div>

        {/* Actions */}
        {!expired ? (
          <div className="flex gap-3 border-t border-[var(--hairline)] px-5 py-4">
            <button
              onClick={handleReject}
              disabled={isActing}
              className="flex-1 flex items-center justify-center gap-2 rounded-xl border border-[var(--hairline)] bg-white/4 px-4 py-2.5 text-sm font-medium text-muted-foreground transition-all hover:border-[var(--critical)]/40 hover:bg-[var(--critical)]/8 hover:text-[var(--critical)] disabled:opacity-50"
            >
              <XCircle className="size-4" /> Cancel
            </button>
            <button
              ref={approveRef}
              onClick={handleApprove}
              disabled={isActing}
              className="flex-1 flex items-center justify-center gap-2 rounded-xl border px-4 py-2.5 text-sm font-semibold transition-all disabled:opacity-50"
              style={{
                borderColor: colorBorder,
                background: `${color}18`,
                color,
              }}
            >
              {isActing
                ? <><span className="size-4 animate-spin rounded-full border-2 border-current border-t-transparent" /> Processing…</>
                : <><CheckCircle2 className="size-4" /> Approve Action</>
              }
            </button>
          </div>
        ) : (
          <div className="border-t border-[var(--hairline)] px-5 py-4">
            <p className="text-center text-sm text-muted-foreground">
              This approval has expired. The operation was not executed.
            </p>
          </div>
        )}

        {/* Audit note */}
        <div className="border-t border-[var(--hairline)] px-5 py-2.5 bg-white/2">
          <p className="text-center font-mono text-[0.55rem] text-muted-foreground">
            This action will be recorded in the AISS immutable audit trail
          </p>
        </div>
      </div>
    </div>
  );
}
