/**
 * AgentPage — AISS Security Agent control center
 * Redesigned to match AISS design system.
 * Uses AISS color tokens, typography, and panel styles.
 */
import React, { useEffect } from "react";
import { AgentProvider, useAgentContext } from "../context/AgentContext";
import { ChatPanel } from "../components/agent/ChatPanel";
import { StatusTimeline } from "../components/agent/StatusTimeline";
import { ApprovalModal } from "../components/agent/ApprovalModal";
import { ReportHistory } from "../components/agent/ReportHistory";
import { ScheduledTasksPanel } from "../components/agent/ScheduledTasksPanel";
import { PageHeader } from "../components/soc/AppShell";
import agentApi from "../api/agentApi";
import { connectWS } from "../lib/api";
import {
  Bot, Shield, FileText, Calendar, Activity,
  CheckCircle2, Clock, AlertTriangle,
} from "lucide-react";

// ─────────────────────────────────────────────────────────────────────────────
// Status pill
// ─────────────────────────────────────────────────────────────────────────────
function TaskStatusBadge({ status }: { status: string }) {
  const cfg = {
    running:           { color: "var(--cyan)",     bg: "rgba(59,130,246,0.10)",  label: "Running" },
    planning:          { color: "var(--cyan)",     bg: "rgba(59,130,246,0.10)",  label: "Planning" },
    completed:         { color: "var(--success)",  bg: "rgba(34,197,94,0.10)",   label: "Completed" },
    awaiting_approval: { color: "#f97316",         bg: "rgba(249,115,22,0.10)",  label: "Awaiting Approval" },
    failed:            { color: "var(--critical)", bg: "rgba(220,38,38,0.10)",   label: "Failed" },
    pending:           { color: "var(--warning)",  bg: "rgba(217,119,6,0.10)",   label: "Pending" },
  }[status] ?? { color: "var(--muted-foreground)", bg: "rgba(255,255,255,0.05)", label: status };

  return (
    <span
      className="rounded-md border px-2.5 py-1 font-mono text-[0.62rem] font-semibold"
      style={{ color: cfg.color, borderColor: `${cfg.color}40`, background: cfg.bg }}
    >
      {cfg.label.toUpperCase()}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Print report button
// ─────────────────────────────────────────────────────────────────────────────
function PrintReportButton() {
  const [status,   setStatus]   = React.useState<"idle" | "loading" | "error">("idle");
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);

  const handlePrint = async () => {
    setStatus("loading");
    setErrorMsg(null);
    try {
      let report = await agentApi.getLatestReport().catch(() => null);
      if (!report || report.status !== "ready") {
        await agentApi.generateReport();
        for (let i = 0; i < 12; i++) {
          await new Promise(r => setTimeout(r, 5000));
          report = await agentApi.getLatestReport().catch(() => null);
          if (report?.status === "ready") break;
        }
      }
      if (!report || report.status !== "ready") {
        throw new Error(
          report?.status === "generating"
            ? "Report is still generating. Please try again in a moment."
            : "Report generation failed."
        );
      }
      const blob = await agentApi.downloadPdf(report.id);
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 30_000);
      setStatus("idle");
    } catch (e: unknown) {
      setStatus("error");
      setErrorMsg((e as Error).message);
    }
  };

  return (
    <div>
      <button
        onClick={handlePrint}
        disabled={status === "loading"}
        className="flex w-full items-center justify-center gap-2 rounded-xl border border-primary/30 bg-primary/10 px-4 py-2.5 text-sm font-semibold text-primary transition-all hover:bg-primary/20 disabled:opacity-50"
      >
        {status === "loading" ? (
          <>
            <span className="size-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
            Generating PDF…
          </>
        ) : (
          <>
            <FileText className="size-4" />
            Generate 7-Day Report
          </>
        )}
      </button>
      {status === "error" && errorMsg && (
        <p className="mt-2 text-center text-[0.7rem] text-[var(--critical)]">{errorMsg}</p>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Inner page (requires AgentProvider)
// ─────────────────────────────────────────────────────────────────────────────
function AgentPageInner() {
  const { state, dispatch } = useAgentContext();
  const {
    chatMessages, isAgentThinking, currentTaskId,
    pendingApproval, executionSteps,
  } = state;

  useEffect(() => { connectWS(); }, []);

  const currentSteps = currentTaskId ? (executionSteps[currentTaskId] ?? []) : [];
  const currentTask  = currentTaskId ? state.tasks[currentTaskId] : null;

  const handleMessage = async (message: string) => {
    dispatch({ type: "CHAT_MESSAGE_SENT", message });
    try {
      const res = await agentApi.chat(message);
      dispatch({
        type: "CHAT_REPLY_RECEIVED",
        taskId:  res.task_id,
        reply:   res.reply,
        status:  res.status,
      });
    } catch (e: unknown) {
      dispatch({
        type:   "CHAT_REPLY_RECEIVED",
        taskId: "",
        reply:  `Error: ${(e as Error).message}`,
        status: "failed",
      });
    }
  };

  const handleApprove = async (id: string) => {
    try { await agentApi.approveAction(id); dispatch({ type: "APPROVAL_CLEARED" }); }
    catch (e) { console.error("Approve failed:", e); }
  };

  const handleReject = async (id: string) => {
    try { await agentApi.rejectAction(id); dispatch({ type: "APPROVAL_CLEARED" }); }
    catch (e) { console.error("Reject failed:", e); }
  };

  return (
    <div className="flex flex-col min-h-[calc(100vh-8rem)]">
      {/* Approval modal — overlays everything */}
      <ApprovalModal
        approval={pendingApproval}
        onApprove={handleApprove}
        onReject={handleReject}
      />

      <PageHeader
        title="AI Security Agent"
        subtitle="Autonomous security orchestration — instructs, executes, reports"
        right={
          currentTask && (
            <div className="flex items-center gap-2">
              <span className="text-[0.72rem] text-muted-foreground">Active task:</span>
              <TaskStatusBadge status={currentTask.status} />
            </div>
          )
        }
      />

      {/* Two-column layout */}
      <div className="flex flex-1 gap-4 min-h-0">
        {/* Left — Chat panel */}
        <div className="flex flex-1 min-w-0 flex-col panel overflow-hidden">
          {/* Panel header */}
          <div className="flex items-center gap-2.5 border-b border-[var(--hairline)] px-4 py-3">
            <div className="flex size-7 items-center justify-center rounded-lg border border-primary/20 bg-primary/10">
              <Bot className="size-3.5 text-primary" />
            </div>
            <p className="text-sm font-semibold">AISS Security Assistant</p>
            <span className="ml-auto rounded-md border border-primary/20 bg-primary/8 px-2 py-0.5 font-mono text-[0.6rem] text-primary">
              AI ACTIVE
            </span>
          </div>

          <div className="flex-1 overflow-hidden">
            <ChatPanel
              messages={chatMessages}
              isLoading={isAgentThinking}
              onMessage={handleMessage}
            />
          </div>
        </div>

        {/* Right — Status, reports, scheduler */}
        <div className="hidden lg:flex w-80 xl:w-96 shrink-0 flex-col gap-3 overflow-y-auto">
          {/* Execution Timeline */}
          <div className="panel overflow-hidden">
            <div className="flex items-center gap-2 border-b border-[var(--hairline)] px-4 py-3">
              <Activity className="size-4 text-primary" />
              <p className="text-sm font-semibold">Execution Timeline</p>
              {isAgentThinking && (
                <span className="ml-auto flex items-center gap-1.5 font-mono text-[0.6rem] text-[var(--cyan)]">
                  <span className="size-1.5 animate-pulse rounded-full bg-[var(--cyan)]" />
                  THINKING
                </span>
              )}
            </div>
            <div className="p-3">
              <StatusTimeline
                taskId={currentTaskId}
                steps={currentSteps}
                overallStatus={currentTask?.status ?? ""}
              />
            </div>
          </div>

          {/* Report generation */}
          <div className="panel overflow-hidden">
            <div className="flex items-center gap-2 border-b border-[var(--hairline)] px-4 py-3">
              <FileText className="size-4 text-primary" />
              <p className="text-sm font-semibold">Security Reports</p>
            </div>
            <div className="p-3 space-y-3">
              <PrintReportButton />
              <ReportHistory />
            </div>
          </div>

          {/* Scheduled tasks */}
          <div className="panel overflow-hidden">
            <div className="flex items-center gap-2 border-b border-[var(--hairline)] px-4 py-3">
              <Calendar className="size-4 text-primary" />
              <p className="text-sm font-semibold">Scheduled Tasks</p>
            </div>
            <div className="p-3">
              <ScheduledTasksPanel />
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Export
// ─────────────────────────────────────────────────────────────────────────────
export default function AgentPage() {
  return (
    <AgentProvider>
      <AgentPageInner />
    </AgentProvider>
  );
}
