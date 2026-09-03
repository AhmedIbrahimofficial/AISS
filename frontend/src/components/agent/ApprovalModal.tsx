/**
 * ApprovalModal — human-in-the-loop approval gate for HIGH/CRITICAL operations
 * Requirements: 4.2, 4.4, 4.5, 4.6
 */
import React, { useEffect, useRef, useState } from "react";
import type { ApprovalRequest } from "../../api/agentApi";

interface ApprovalModalProps {
  approval: ApprovalRequest | null;
  onApprove: (id: string) => void;
  onReject: (id: string) => void;
}

function RiskBadge({ level }: { level: string }) {
  const styles: Record<string, string> = {
    HIGH:     "bg-orange-500/20 text-orange-300 border border-orange-500/40",
    CRITICAL: "bg-red-600/20 text-red-300 border border-red-600/40",
    MEDIUM:   "bg-yellow-500/20 text-yellow-300 border border-yellow-500/40",
    LOW:      "bg-green-500/20 text-green-300 border border-green-500/40",
  };
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${styles[level] ?? styles["LOW"]}`}>
      {level}
    </span>
  );
}

export function ApprovalModal({ approval, onApprove, onReject }: ApprovalModalProps) {
  const [secondsLeft, setSecondsLeft] = useState(3600);
  const [isActing, setIsActing] = useState(false);
  const [expired, setExpired] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const approveRef = useRef<HTMLButtonElement>(null);

  // Reset timer whenever approval changes
  useEffect(() => {
    if (!approval) return;
    setSecondsLeft(3600);
    setExpired(false);
    setIsActing(false);
    approveRef.current?.focus();

    intervalRef.current = setInterval(() => {
      setSecondsLeft((s) => {
        if (s <= 1) {
          clearInterval(intervalRef.current!);
          setExpired(true);
          return 0;
        }
        return s - 1;
      });
    }, 1000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [approval?.id]);

  if (!approval) return null;

  const handleApprove = async () => {
    if (isActing || expired) return;
    setIsActing(true);
    try { onApprove(approval.id); } finally { setIsActing(false); }
  };

  const handleReject = async () => {
    if (isActing) return;
    setIsActing(true);
    try { onReject(approval.id); } finally { setIsActing(false); }
  };

  const formatTime = (secs: number) => {
    const m = Math.floor(secs / 60);
    const s = secs % 60;
    return `${m}:${String(s).padStart(2, "0")}`;
  };

  return (
    /* Backdrop */
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-labelledby="approval-title"
    >
      <div
        className={`w-full max-w-lg mx-4 rounded-2xl shadow-2xl border ${
          approval.risk_level === "CRITICAL"
            ? "bg-gray-950 border-red-700/60"
            : "bg-gray-950 border-orange-600/50"
        } p-6`}
      >
        {/* Header */}
        <div className="flex items-start gap-3 mb-5">
          <div className={`mt-0.5 p-2 rounded-lg ${approval.risk_level === "CRITICAL" ? "bg-red-600/20" : "bg-orange-500/20"}`}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"
              className={approval.risk_level === "CRITICAL" ? "text-red-400" : "text-orange-400"}>
              <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z" />
              <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
            </svg>
          </div>
          <div>
            <h2 id="approval-title" className="text-base font-bold text-white">Approval Required</h2>
            <p className="text-xs text-gray-400 mt-0.5">This operation requires your explicit authorisation</p>
          </div>
          <div className="ml-auto">
            <RiskBadge level={approval.risk_level} />
          </div>
        </div>

        {/* Details */}
        <div className="space-y-3 mb-5">
          <DetailRow label="Operation" value={approval.tool_name} mono />
          <DetailRow label="What will happen" value={approval.description} />
          <DetailRow label="Why it is required" value={approval.reason} />
          {approval.affected_resource && (
            <DetailRow label="Affected resource" value={approval.affected_resource} mono />
          )}
          {approval.estimated_impact && (
            <DetailRow label="Estimated impact" value={approval.estimated_impact} />
          )}
        </div>

        {/* Countdown */}
        <div className={`flex items-center gap-2 text-xs mb-5 px-3 py-2 rounded-lg ${
          expired ? "bg-red-900/30 text-red-300" : "bg-gray-800 text-gray-400"
        }`}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
          </svg>
          {expired
            ? "Approval window expired"
            : <>Auto-expires in <span className="font-mono font-bold text-white ml-1">{formatTime(secondsLeft)}</span></>
          }
        </div>

        {expired ? (
          <p className="text-center text-sm text-gray-500 italic">This approval has expired and the operation was cancelled.</p>
        ) : (
          <div className="flex gap-3">
            <button
              ref={approveRef}
              onClick={handleApprove}
              disabled={isActing}
              className="flex-1 py-2.5 rounded-xl bg-green-600 hover:bg-green-500 disabled:opacity-50 text-white font-semibold text-sm transition-colors"
            >
              {isActing ? "Processing…" : "✓ Approve"}
            </button>
            <button
              onClick={handleReject}
              disabled={isActing}
              className="flex-1 py-2.5 rounded-xl bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white font-semibold text-sm transition-colors"
            >
              ✕ Reject
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="bg-gray-900 rounded-lg px-3 py-2.5">
      <p className="text-xs text-gray-500 mb-0.5">{label}</p>
      <p className={`text-sm text-gray-200 ${mono ? "font-mono" : ""}`}>{value}</p>
    </div>
  );
}
