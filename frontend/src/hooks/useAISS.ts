/**
 * AISS React Hooks — connects components to the live backend.
 * All hooks are safe to use even when the backend is offline
 * (they fall back gracefully to empty/null data).
 */
import { useEffect, useRef, useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  connectWS, disconnectWS, onWSEvent, sendWSMessage, getToken,
  getHealth, getSystemHealth, getActiveThreats, getThreatStats,
  getThreats, resolveThreat, getAgents, getAgentStats,
  getTopologyMap, enrichIP, llmAnalyze, socChat, triggerScan,
  getLibraries, getLLMProviders, getWizardQuestions,
  type Threat, type WizardQuestion,
} from "@/lib/api";

// ── Connection status ──────────────────────────────────────────────────

export function useBackendStatus() {
  const [online, setOnline] = useState(false);
  const { data, error } = useQuery({
    queryKey: ["health"],
    queryFn:  getHealth,
    refetchInterval: 10_000,
    retry: false,
  });
  useEffect(() => { setOnline(!!data && !error); }, [data, error]);
  return { online, health: data };
}

// ── WebSocket connection + auto-popup ─────────────────────────────────

export function useWebSocket(onPopupQuestion?: (q: WizardQuestion) => void) {
  const [connected, setConnected]             = useState(false);
  const [lastEvent,  setLastEvent]            = useState<Record<string, unknown> | null>(null);
  const qc = useQueryClient();

  useEffect(() => {
    if (!getToken()) return;

    const ws = connectWS();
    if (!ws) return;

    const off = onWSEvent((evt) => {
      setLastEvent(evt as Record<string, unknown>);

      switch (evt.event) {
        case "authenticated":
          setConnected(true);
          break;

        case "threat_detected": {
          const t = evt.threat as Threat;
          if (t.severity === "critical" || t.severity === "high") {
            toast.error(`[${t.severity.toUpperCase()}] ${t.type}`, {
              description: `${t.description?.slice(0, 80)} — source: ${t.source}`,
              duration: 8000,
            });
          }
          void qc.invalidateQueries({ queryKey: ["threats"] });
          void qc.invalidateQueries({ queryKey: ["threat-stats"] });
          break;
        }

        case "threat_resolved":
          void qc.invalidateQueries({ queryKey: ["threats"] });
          break;

        case "monitoring_started":
          toast.success("AISS Monitoring started");
          break;

        case "wizard_start": {
          // Backend sends unanswered wizard questions — show the first as popup
          const questions = evt.questions as WizardQuestion[];
          if (questions?.length && onPopupQuestion) {
            onPopupQuestion(questions[0]!);
          }
          break;
        }

        case "popup_question": {
          const q = evt.question as WizardQuestion;
          if (q && onPopupQuestion) onPopupQuestion(q);
          break;
        }

        case "popup_answered":
          toast.success("Setting saved");
          break;
      }
    });

    return () => {
      off();
      setConnected(false);
    };
  }, [qc, onPopupQuestion]);

  const startMonitoring = useCallback(() => sendWSMessage("start_monitoring"), []);
  const stopMonitoring  = useCallback(() => sendWSMessage("stop_monitoring"),  []);
  const answerPopup     = useCallback((id: string, value: string) => {
    sendWSMessage("popup_answer", { question_id: id, value });
  }, []);
  const dismissPopup    = useCallback((id: string) => {
    sendWSMessage("popup_dismiss", { question_id: id });
  }, []);

  return { connected, lastEvent, startMonitoring, stopMonitoring, answerPopup, dismissPopup };
}

// ── Threats ────────────────────────────────────────────────────────────

export function useThreats() {
  return useQuery({
    queryKey:       ["threats", "active"],
    queryFn:        getActiveThreats,
    refetchInterval: 5_000,
    select:         (d) => d.threats,
  });
}

export function useAllThreats() {
  return useQuery({
    queryKey:       ["threats"],
    queryFn:        getThreats,
    refetchInterval: 10_000,
    select:         (d) => d.threats,
  });
}

export function useThreatStats() {
  return useQuery({
    queryKey:       ["threat-stats"],
    queryFn:        getThreatStats,
    refetchInterval: 5_000,
  });
}

export function useResolve() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, note }: { id: string; note?: string }) =>
      resolveThreat(id, note ?? "Resolved from dashboard"),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["threats"] });
      toast.success("Threat resolved");
    },
    onError: (e) => toast.error(`Failed: ${String(e)}`),
  });
}

// ── System health ──────────────────────────────────────────────────────

export function useSystemHealth() {
  return useQuery({
    queryKey:       ["system-health"],
    queryFn:        getSystemHealth,
    refetchInterval: 8_000,
  });
}

export function useLibraries() {
  return useQuery({
    queryKey: ["libraries"],
    queryFn:  getLibraries,
    staleTime: 60_000,
  });
}

export function useLLMProviders() {
  return useQuery({
    queryKey: ["llm-providers"],
    queryFn:  getLLMProviders,
    staleTime: 60_000,
  });
}

// ── Agents ────────────────────────────────────────────────────────────

export function useAgents() {
  return useQuery({
    queryKey:       ["agents"],
    queryFn:        getAgents,
    refetchInterval: 10_000,
  });
}

export function useAgentStats() {
  return useQuery({
    queryKey:       ["agent-stats"],
    queryFn:        getAgentStats,
    refetchInterval: 5_000,
  });
}

// ── Topology ──────────────────────────────────────────────────────────

export function useTopologyMap() {
  return useQuery({
    queryKey:       ["topology"],
    queryFn:        getTopologyMap,
    refetchInterval: 30_000,
  });
}

// ── Scan ──────────────────────────────────────────────────────────────

export function useTriggerScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: triggerScan,
    onSuccess:  () => {
      toast.success("Scan started");
      void qc.invalidateQueries({ queryKey: ["threats"] });
    },
    onError: (e) => toast.error(`Scan failed: ${String(e)}`),
  });
}

// ── IP enrichment ──────────────────────────────────────────────────────

export function useEnrichIP(ip: string | null) {
  return useQuery({
    queryKey:  ["enrich-ip", ip],
    queryFn:   () => enrichIP(ip!),
    enabled:   !!ip,
    staleTime: 300_000,
  });
}

// ── LLM analysis ──────────────────────────────────────────────────────

export function useLLMAnalyze() {
  return useMutation({
    mutationFn: ({ text }: { text: string }) => llmAnalyze(text),
    onError:    (e) => toast.error(`AI analysis failed: ${String(e)}`),
  });
}

// ── SOC Chat ──────────────────────────────────────────────────────────

export function useSOCChat() {
  const [messages, setMessages] = useState<{ role: "user" | "ai"; text: string }[]>([]);
  const [loading,  setLoading]  = useState(false);

  const send = useCallback(async (text: string) => {
    setMessages((m) => [...m, { role: "user", text }]);
    setLoading(true);
    try {
      const r = await socChat(text);
      setMessages((m) => [...m, { role: "ai", text: r.response }]);
    } catch (e) {
      setMessages((m) => [...m, { role: "ai", text: `Error: ${String(e)}` }]);
    } finally {
      setLoading(false);
    }
  }, []);

  return { messages, loading, send };
}

// ── Wizard ────────────────────────────────────────────────────────────

export function useWizard() {
  return useQuery({
    queryKey: ["wizard"],
    queryFn:  getWizardQuestions,
    staleTime: 30_000,
  });
}
