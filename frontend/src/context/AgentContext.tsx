/**
 * Agent Context — manages agent state and WebSocket event dispatch
 * Requirements: 1.3
 */
import React, {
  createContext, useContext, useReducer, useEffect,
  useCallback, ReactNode
} from "react";
import { onWSEvent } from "../lib/api";
import type {
  AgentTask, ApprovalRequest, ChatMessage, ExecutionStep, ScheduledTask, Report
} from "../api/agentApi";

// ── State ─────────────────────────────────────────────────────────────

interface AgentState {
  tasks: Record<string, AgentTask>;
  currentTaskId: string | null;
  pendingApproval: ApprovalRequest | null;
  chatMessages: ChatMessage[];
  executionSteps: Record<string, ExecutionStep[]>; // taskId -> steps
  isAgentThinking: boolean;
  reports: Report[];
  scheduledTasks: ScheduledTask[];
}

const initialState: AgentState = {
  tasks: {},
  currentTaskId: null,
  pendingApproval: null,
  chatMessages: [],
  executionSteps: {},
  isAgentThinking: false,
  reports: [],
  scheduledTasks: [],
};

// ── Actions ───────────────────────────────────────────────────────────

type AgentAction =
  | { type: "CHAT_MESSAGE_SENT"; message: string }
  | { type: "CHAT_REPLY_RECEIVED"; taskId: string; reply: string; status: string }
  | { type: "TASK_CREATED"; taskId: string; status: string; description: string }
  | { type: "TASK_STEP_STARTED"; taskId: string; stepIndex: number; toolName: string }
  | { type: "TASK_STEP_COMPLETE"; taskId: string; stepIndex: number; toolName: string; status: string; durationMs?: number; resultSummary?: string }
  | { type: "APPROVAL_REQUIRED"; approval: ApprovalRequest }
  | { type: "APPROVAL_CLEARED" }
  | { type: "TASK_COMPLETE"; taskId: string; status: string; summary: string }
  | { type: "TASK_FAILED"; taskId: string; error: string }
  | { type: "SET_THINKING"; value: boolean }
  | { type: "REPORTS_LOADED"; reports: Report[] }
  | { type: "SCHEDULED_TASKS_LOADED"; tasks: ScheduledTask[] }
  | { type: "CLEAR_CHAT" };

function reducer(state: AgentState, action: AgentAction): AgentState {
  switch (action.type) {
    case "CHAT_MESSAGE_SENT":
      return {
        ...state,
        isAgentThinking: true,
        chatMessages: [
          ...state.chatMessages,
          { role: "user", content: action.message, created_at: new Date().toISOString() },
        ],
      };

    case "CHAT_REPLY_RECEIVED":
      return {
        ...state,
        isAgentThinking: false,
        currentTaskId: action.taskId,
        chatMessages: [
          ...state.chatMessages,
          {
            role: "assistant",
            content: action.reply,
            task_id: action.taskId,
            created_at: new Date().toISOString(),
          },
        ],
      };

    case "TASK_CREATED":
      return {
        ...state,
        currentTaskId: action.taskId,
        tasks: {
          ...state.tasks,
          [action.taskId]: {
            id: action.taskId,
            status: action.status,
            description: action.description,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            executions: [],
            approvals: [],
          },
        },
        executionSteps: { ...state.executionSteps, [action.taskId]: [] },
      };

    case "TASK_STEP_STARTED": {
      const steps = [...(state.executionSteps[action.taskId] ?? [])];
      const existing = steps.findIndex((s) => s.step_index === action.stepIndex);
      const newStep: ExecutionStep = {
        step_index: action.stepIndex,
        tool_name: action.toolName,
        status: "running",
      };
      if (existing >= 0) steps[existing] = newStep; else steps.push(newStep);
      return { ...state, executionSteps: { ...state.executionSteps, [action.taskId]: steps } };
    }

    case "TASK_STEP_COMPLETE": {
      const steps = [...(state.executionSteps[action.taskId] ?? [])];
      const idx = steps.findIndex((s) => s.step_index === action.stepIndex);
      const updated: ExecutionStep = {
        step_index: action.stepIndex,
        tool_name: action.toolName,
        status: action.status,
        duration_ms: action.durationMs,
        result_summary: action.resultSummary,
      };
      if (idx >= 0) steps[idx] = updated; else steps.push(updated);
      return { ...state, executionSteps: { ...state.executionSteps, [action.taskId]: steps } };
    }

    case "APPROVAL_REQUIRED":
      return { ...state, pendingApproval: action.approval };

    case "APPROVAL_CLEARED":
      return { ...state, pendingApproval: null };

    case "TASK_COMPLETE":
    case "TASK_FAILED": {
      const task = state.tasks[action.taskId];
      return {
        ...state,
        isAgentThinking: false,
        tasks: task
          ? { ...state.tasks, [action.taskId]: { ...task, status: action.status } }
          : state.tasks,
      };
    }

    case "SET_THINKING":
      return { ...state, isAgentThinking: action.value };

    case "REPORTS_LOADED":
      return { ...state, reports: action.reports };

    case "SCHEDULED_TASKS_LOADED":
      return { ...state, scheduledTasks: action.tasks };

    case "CLEAR_CHAT":
      return { ...state, chatMessages: [], currentTaskId: null };

    default:
      return state;
  }
}

// ── Context ───────────────────────────────────────────────────────────

interface AgentContextValue {
  state: AgentState;
  dispatch: React.Dispatch<AgentAction>;
}

const AgentContext = createContext<AgentContextValue | null>(null);

export function AgentProvider({ children }: { children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState);

  // Subscribe to WebSocket agent_* events
  useEffect(() => {
    const unsub = onWSEvent((event) => {
      const { event: evType, ...payload } = event;

      if (evType === "agent_task_created") {
        dispatch({
          type: "TASK_CREATED",
          taskId: payload.task_id as string,
          status: payload.status as string,
          description: payload.description as string,
        });
      } else if (evType === "agent_step_started") {
        dispatch({
          type: "TASK_STEP_STARTED",
          taskId: payload.task_id as string,
          stepIndex: payload.step_index as number,
          toolName: payload.tool_name as string,
        });
      } else if (evType === "agent_step_complete") {
        dispatch({
          type: "TASK_STEP_COMPLETE",
          taskId: payload.task_id as string,
          stepIndex: payload.step_index as number,
          toolName: payload.tool_name as string,
          status: payload.status as string,
          durationMs: payload.duration_ms as number | undefined,
          resultSummary: payload.result_summary as string | undefined,
        });
      } else if (evType === "agent_approval_required") {
        dispatch({
          type: "APPROVAL_REQUIRED",
          approval: {
            id: payload.approval_id as string,
            task_id: payload.task_id as string,
            tool_name: payload.tool_name as string,
            risk_level: payload.risk_level as string,
            description: payload.description as string,
            reason: payload.reason as string,
            affected_resource: payload.affected_resource as string | undefined,
            estimated_impact: payload.estimated_impact as string | undefined,
            status: "pending",
            created_at: new Date().toISOString(),
          },
        });
      } else if (evType === "agent_task_complete") {
        dispatch({
          type: "TASK_COMPLETE",
          taskId: payload.task_id as string,
          status: payload.status as string,
          summary: payload.summary as string,
        });
      } else if (evType === "agent_task_failed") {
        dispatch({
          type: "TASK_FAILED",
          taskId: payload.task_id as string,
          status: "failed",
          error: payload.error as string,
        } as AgentAction);
      }
    });
    return unsub;
  }, []);

  return (
    <AgentContext.Provider value={{ state, dispatch }}>
      {children}
    </AgentContext.Provider>
  );
}

export function useAgentContext(): AgentContextValue {
  const ctx = useContext(AgentContext);
  if (!ctx) throw new Error("useAgentContext must be used within AgentProvider");
  return ctx;
}
