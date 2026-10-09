/**
 * StatusTimeline — real-time execution step display
 * Redesigned to match AISS design system.
 */
import { useState } from "react";
import { CheckCircle2, XCircle, Loader2, Clock, AlertTriangle, ChevronDown } from "lucide-react";
import type { ExecutionStep } from "../../api/agentApi";

interface StatusTimelineProps {
  taskId:        string | null;
  steps:         ExecutionStep[];
  overallStatus: string;
}

function StepIcon({ status }: { status: string }) {
  if (status === "running")
    return <Loader2 className="size-4 animate-spin text-[var(--cyan)]" />;
  if (status === "completed")
    return <CheckCircle2 className="size-4 text-[var(--success)]" />;
  if (status === "failed" || status === "timed_out")
    return <XCircle className="size-4 text-[var(--critical)]" />;
  if (status === "awaiting_approval" || status === "approval_rejected")
    return <AlertTriangle className="size-4 text-[var(--warning)]" />;
  // pending
  return <div className="size-4 rounded-full border-2 border-[var(--hairline)] bg-white/3" />;
}

const STEP_COLOR: Record<string, string> = {
  completed:          "var(--success)",
  running:            "var(--cyan)",
  failed:             "var(--critical)",
  timed_out:          "var(--critical)",
  awaiting_approval:  "var(--warning)",
  approval_rejected:  "var(--critical)",
};

const OVERALL_COLOR: Record<string, string> = {
  completed: "var(--success)",
  running:   "var(--cyan)",
  planning:  "var(--cyan)",
  failed:    "var(--critical)",
  awaiting_approval: "#f97316",
  pending:   "var(--warning)",
};

export function StatusTimeline({ taskId, steps, overallStatus }: StatusTimelineProps) {
  const [expanded, setExpanded] = useState<Record<number, boolean>>({});
  const toggle = (idx: number) => setExpanded(p => ({ ...p, [idx]: !p[idx] }));

  if (steps.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-6 text-center">
        <Clock className="size-8 text-muted-foreground opacity-20" />
        <p className="text-[0.72rem] text-muted-foreground">
          No steps yet. Send a command to start.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-0.5">
      {steps.map((step, i) => {
        const color = STEP_COLOR[step.status] ?? "var(--muted-foreground)";
        const hasDetail = !!(step.result_summary || step.error);

        return (
          <div key={step.step_index} className="flex gap-2.5">
            {/* Icon + line */}
            <div className="flex flex-col items-center pt-1">
              <StepIcon status={step.status} />
              {i < steps.length - 1 && (
                <div className="mt-1 w-px flex-1 bg-[var(--hairline)]" style={{ minHeight: 12 }} />
              )}
            </div>

            {/* Content */}
            <div className={`flex-1 min-w-0 pb-2 ${i < steps.length - 1 ? "" : ""}`}>
              <div
                className={`flex items-center gap-2 ${hasDetail ? "cursor-pointer" : ""}`}
                onClick={() => hasDetail && toggle(step.step_index)}
              >
                <span className="font-mono text-[0.58rem] text-muted-foreground">
                  {step.step_index + 1}.
                </span>
                <span className="flex-1 min-w-0 truncate text-[0.78rem] font-medium">
                  {step.tool_name.replace(/_/g, " ")}
                </span>
                <span className="shrink-0 font-mono text-[0.6rem] font-semibold" style={{ color }}>
                  {step.status}
                </span>
                {step.duration_ms != null && (
                  <span className="shrink-0 font-mono text-[0.58rem] text-muted-foreground">
                    {(step.duration_ms / 1000).toFixed(1)}s
                  </span>
                )}
                {hasDetail && (
                  <ChevronDown
                    className={`size-3 shrink-0 text-muted-foreground transition-transform ${
                      expanded[step.step_index] ? "rotate-180" : ""
                    }`}
                  />
                )}
              </div>

              {expanded[step.step_index] && hasDetail && (
                <div className={`mt-1.5 rounded-lg border px-3 py-2 font-mono text-[0.65rem] leading-relaxed ${
                  step.error
                    ? "border-[var(--critical)]/20 bg-[var(--critical)]/5 text-[var(--critical)]"
                    : "border-[var(--hairline)] bg-white/3 text-muted-foreground"
                }`}>
                  {step.error ?? step.result_summary}
                </div>
              )}
            </div>
          </div>
        );
      })}

      {/* Overall status */}
      {overallStatus && (
        <div className="border-t border-[var(--hairline)] pt-2 mt-1">
          <div className="flex items-center gap-2">
            <span className="label-cap text-[0.58rem]">Task status</span>
            <span
              className="font-mono text-[0.6rem] font-semibold"
              style={{ color: OVERALL_COLOR[overallStatus] ?? "var(--muted-foreground)" }}
            >
              {overallStatus.replace(/_/g, " ").toUpperCase()}
            </span>
            {taskId && (
              <span className="ml-auto font-mono text-[0.55rem] text-muted-foreground">
                #{taskId.slice(0, 8)}
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
