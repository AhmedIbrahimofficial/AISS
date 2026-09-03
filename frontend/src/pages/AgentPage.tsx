/**
 * AgentPage — AISS Security Agent control center
 * Two-column layout: chat left, tools/status right
 * Requirements: 1.1, 1.3, 4.2, 27.x
 */
import React, { useEffect } from "react";
import { AgentProvider, useAgentContext } from "../context/AgentContext";
import { ChatPanel } from "../components/agent/ChatPanel";
import { StatusTimeline } from "../components/agent/StatusTimeline";
import { ApprovalModal } from "../components/agent/ApprovalModal";
import { ReportHistory } from "../components/agent/ReportHistory";
import { ScheduledTasksPanel } from "../components/agent/ScheduledTasksPanel";
import agentApi from "../api/agentApi";
import { connectWS } from "../lib/api";

function AgentPageInner() {
  const { state, dispatch } = useAgentContext();
  const { chatMessages, isAgentThinking, currentTaskId, pendingApproval, executionSteps } = state;

  // Connect WebSocket on mount
  useEffect(() => {
    connectWS();
  }, []);

  const currentSteps = currentTaskId ? (executionSteps[currentTaskId] ?? []) : [];
  const currentTask = currentTaskId ? state.tasks[currentTaskId] : null;

  const handleMessage = async (message: string) => {
    dispatch({ type: "CHAT_MESSAGE_SENT", message });
    try {
      const res = await agentApi.chat(message);
      dispatch({
        type: "CHAT_REPLY_RECEIVED",
        taskId: res.task_id,
        reply: res.reply,
        status: res.status,
      });
    } catch (e: unknown) {
      dispatch({
        type: "CHAT_REPLY_RECEIVED",
        taskId: "",
        reply: `Error: ${(e as Error).message}`,
        status: "failed",
      });
    }
  };

  const handleApprove = async (id: string) => {
    try {
      await agentApi.approveAction(id);
      dispatch({ type: "APPROVAL_CLEARED" });
    } catch (e: unknown) {
      console.error("Approve failed:", e);
    }
  };

  const handleReject = async (id: string) => {
    try {
      await agentApi.rejectAction(id);
      dispatch({ type: "APPROVAL_CLEARED" });
    } catch (e: unknown) {
      console.error("Reject failed:", e);
    }
  };

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      {/* Approval modal (overlay) */}
      <ApprovalModal
        approval={pendingApproval}
        onApprove={handleApprove}
        onReject={handleReject}
      />

      {/* Page header */}
      <div className="border-b border-gray-800 bg-gray-900 px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-blue-600 flex items-center justify-center">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            </svg>
          </div>
          <div>
            <h1 className="text-lg font-bold text-white">AISS Security Agent</h1>
            <p className="text-xs text-gray-400">Autonomous AI security orchestration · Real data · No fabrications</p>
          </div>
          {currentTask && (
            <div className="ml-auto flex items-center gap-2">
              <span className="text-xs text-gray-500">Active task:</span>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                currentTask.status === "running" ? "bg-blue-600/20 text-blue-300" :
                currentTask.status === "completed" ? "bg-green-600/20 text-green-300" :
                currentTask.status === "awaiting_approval" ? "bg-orange-600/20 text-orange-300" :
                "bg-gray-700 text-gray-400"
              }`}>
                {currentTask.status}
              </span>
            </div>
          )}
        </div>
      </div>

      {/* Main content */}
      <div className="flex h-[calc(100vh-73px)]">
        {/* Left: Chat panel */}
        <div className="flex-1 min-w-0 p-4 flex flex-col">
          <ChatPanel
            messages={chatMessages}
            isLoading={isAgentThinking}
            onMessage={handleMessage}
          />
        </div>

        {/* Right: Status + Reports + Scheduler */}
        <div className="w-96 shrink-0 border-l border-gray-800 overflow-y-auto p-4 space-y-4">
          {/* Execution timeline */}
          <StatusTimeline
            taskId={currentTaskId}
            steps={currentSteps}
            overallStatus={currentTask?.status ?? ""}
          />

          {/* Weekly report button */}
          <div className="bg-gray-950 rounded-xl border border-gray-800 p-4">
            <PrintReportButton />
          </div>

          {/* Report history */}
          <ReportHistory />

          {/* Scheduled tasks */}
          <ScheduledTasksPanel />
        </div>
      </div>
    </div>
  );
}

function PrintReportButton() {
  const [status, setStatus] = React.useState<"idle" | "loading" | "error">("idle");
  const [errorMsg, setErrorMsg] = React.useState<string | null>(null);

  const handlePrint = async () => {
    setStatus("loading");
    setErrorMsg(null);
    try {
      // Try to get the latest ready report
      let report = await agentApi.getLatestReport().catch(() => null);

      // If no ready report, generate one
      if (!report || report.status !== "ready") {
        await agentApi.generateReport();
        // Poll for up to 60s
        for (let i = 0; i < 12; i++) {
          await new Promise((r) => setTimeout(r, 5000));
          report = await agentApi.getLatestReport().catch(() => null);
          if (report?.status === "ready") break;
        }
      }

      if (!report || report.status !== "ready") {
        throw new Error(report?.status === "generating"
          ? "Report is still generating. Please try again in a moment."
          : "Report generation failed.");
      }

      // Download and open PDF
      const blob = await agentApi.downloadPdf(report.id);
      const url = URL.createObjectURL(blob);
      window.open(url, "_blank");
      setTimeout(() => URL.revokeObjectURL(url), 30000);
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
        className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white font-semibold text-sm transition-colors flex items-center justify-center gap-2"
      >
        {status === "loading" ? (
          <><span className="w-4 h-4 rounded-full border-2 border-white border-t-transparent animate-spin" />Generating PDF…</>
        ) : (
          <>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="6 9 6 2 18 2 18 9" />
              <path d="M6 18H4a2 2 0 01-2-2v-5a2 2 0 012-2h16a2 2 0 012 2v5a2 2 0 01-2 2h-2" />
              <rect x="6" y="14" width="12" height="8" />
            </svg>
            Print Your 7-Day Report
          </>
        )}
      </button>
      {status === "error" && errorMsg && (
        <p className="text-xs text-red-400 mt-2 text-center">{errorMsg}</p>
      )}
    </div>
  );
}

export default function AgentPage() {
  return (
    <AgentProvider>
      <AgentPageInner />
    </AgentProvider>
  );
}
