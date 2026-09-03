/**
 * StatusTimeline — real-time execution step display
 * Requirements: 1.3, 5.2
 */
import React, { useState } from "react";
import type { ExecutionStep } from "../../api/agentApi";

interface StatusTimelineProps {
  taskId: string | null;
  steps: ExecutionStep[];
  overallStatus: string;
}

function StatusIcon({ status }: { status: string }) {
  if (status === "running") {
    return (
      <div className="w-5 h-5 rounded-full border-2 border-blue-400 border-t-transparent animate-spin" />
    );
  }
  if (status === "completed") {
    return (
      <div className="w-5 h-5 rounded-full bg-green-500 flex items-center justify-center">
        <svg width="11" height="11" viewBox="0 0 12 12" fill="white">
          <path d="M1.5 6L4.5 9L10.5 3" stroke="white" strokeWidth="1.5" strokeLinecap="round" fill="none" />
        </svg>
      </div>
    );
  }
  if (status === "failed" || status === "timed_out") {
    return (
      <div className="w-5 h-5 rounded-full bg-red-500 flex items-center justify-center">
        <svg width="10" height="10" viewBox="0 0 10 10" fill="white">
          <path d="M2 2L8 8M8 2L2 8" stroke="white" strokeWidth="1.5" strokeLinecap="round" />
        </svg>
      </div>
    );
  }
  if (status === "awaiting_approval" || status === "approval_rejected") {
    return (
      <div className="w-5 h-5 rounded-full bg-orange-500 flex items-center justify-center text-white text-xs font-bold">!</div>
    );
  }
  // pending / default
  return <div className="w-5 h-5 rounded-full border-2 border-gray-600 bg-gray-800" />;
}

function statusColor(status: string): string {
  if (status === "completed") return "text-green-400";
  if (status === "running") return "text-blue-400";
  if (status === "failed" || status === "timed_out") return "text-red-400";
  if (status === "awaiting_approval") return "text-orange-400";
  return "text-gray-500";
}

export function StatusTimeline({ taskId, steps, overallStatus }: StatusTimelineProps) {
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});

  const toggle = (idx: number) => setExpanded((p) => ({ ...p, [idx]: !p[idx] }));

  return (
    <div className="bg-gray-950 rounded-xl border border-gray-800 p-4">
      {/* Header */}
      <div className="flex items-center gap-2 mb-3">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="text-blue-400">
          <circle cx="12" cy="12" r="10" /><polyline points="12 6 12 12 16 14" />
        </svg>
        <span className="text-sm font-semibold text-gray-200">Execution Timeline</span>
        {taskId && <span className="ml-auto text-xs text-gray-600">#{taskId.slice(0, 8)}</span>}
      </div>

      {steps.length === 0 ? (
        <p className="text-xs text-gray-600 italic">No steps yet. Send a message to start.</p>
      ) : (
        <div className="space-y-2">
          {steps.map((step) => (
            <div key={step.step_index} className="flex gap-3">
              {/* Icon + vertical line */}
              <div className="flex flex-col items-center">
                <StatusIcon status={step.status} />
                <div className="w-px flex-1 bg-gray-800 mt-1" />
              </div>

              {/* Content */}
              <div className="pb-3 flex-1 min-w-0">
                <div
                  className="flex items-center gap-2 cursor-pointer"
                  onClick={() => toggle(step.step_index)}
                >
                  <span className="text-xs font-mono text-gray-400">{step.step_index + 1}.</span>
                  <span className="text-sm text-gray-200 font-medium truncate">{step.tool_name}</span>
                  <span className={`ml-auto text-xs font-medium shrink-0 ${statusColor(step.status)}`}>
                    {step.status}
                  </span>
                  {step.duration_ms && (
                    <span className="text-xs text-gray-600 shrink-0">{(step.duration_ms / 1000).toFixed(1)}s</span>
                  )}
                  {step.result_summary && (
                    <svg
                      width="12" height="12" viewBox="0 0 12 12" fill="none"
                      className={`text-gray-500 shrink-0 transition-transform ${expanded[step.step_index] ? "rotate-180" : ""}`}
                    >
                      <path d="M2 4L6 8L10 4" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
                    </svg>
                  )}
                </div>

                {/* Expanded result summary */}
                {expanded[step.step_index] && (step.result_summary || step.error) && (
                  <div className={`mt-1.5 text-xs rounded-lg px-3 py-2 font-mono ${
                    step.error
                      ? "bg-red-950/40 border border-red-900 text-red-300"
                      : "bg-gray-900 border border-gray-800 text-gray-400"
                  }`}>
                    {step.error || step.result_summary}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Overall status */}
      {overallStatus && (
        <div className={`mt-2 pt-2 border-t border-gray-800 text-xs font-medium ${statusColor(overallStatus)}`}>
          Task: {overallStatus}
        </div>
      )}
    </div>
  );
}
