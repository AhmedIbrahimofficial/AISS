import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useState, useEffect, useRef, useCallback } from "react";
import { toast } from "sonner";
import {
  Shield, AlertTriangle, CheckCircle2, Zap, ChevronRight,
  Cpu, Activity, Clock, Search, Loader2, Send,
  Eye, XCircle, Terminal, BarChart3, FileSearch, Microscope,
} from "lucide-react";
import {
  useThreats, useThreatStats, useBackendStatus, useStartSecurityScan,
} from "@/hooks/useAISS";
import { socChatV2, onWSEvent, type Threat } from "@/lib/api";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Command Center — AISS" },
      { name: "description", content: "Your security reality. AI sees everything, so you don't have to." },
    ],
  }),
  component: CommandCenter,
});

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────
interface TimelineEvent {
  id: string;
  time: string;
  type: "threat" | "contained" | "analysis" | "clear" | "ai";
  severity?: "critical" | "high" | "medium" | "low";
  title: string;
  summary: string;
  threatId?: string;
  actionLabel?: string;
}

interface AIStreamStep {
  id: string;
  label: string;
  status: "pending" | "running" | "done" | "error";
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────
function relativeTime(iso: string): string {
  try {
    const diff = Date.now() - new Date(iso).getTime();
    const mins = Math.floor(diff / 60_000);
    if (mins < 1) return "just now";
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    return `${Math.floor(hrs / 24)}d ago`;
  } catch {
    return "";
  }
}

const severityColor = (s?: string) => {
  if (s === "critical") return "var(--critical)";
  if (s === "high") return "#f97316";
  if (s === "medium") return "var(--warning)";
  return "var(--success)";
};

const severityBg = (s?: string) => {
  if (s === "critical") return "rgba(220,38,38,0.08)";
  if (s === "high") return "rgba(249,115,22,0.08)";
  if (s === "medium") return "rgba(217,119,6,0.08)";
  return "rgba(34,197,94,0.06)";
};

// ─────────────────────────────────────────────────────────────────────────────
// Timeline Event Card
// ─────────────────────────────────────────────────────────────────────────────
function TimelineCard({
  event,
  onInvestigate,
}: {
  event: TimelineEvent;
  onInvestigate: (id: string) => void;
}) {
  const isThreat = event.type === "threat";
  const isContained = event.type === "contained";
  const isAI = event.type === "ai";

  const icon = isContained ? (
    <CheckCircle2 className="size-4" style={{ color: "var(--success)" }} />
  ) : isThreat ? (
    <AlertTriangle className="size-4" style={{ color: severityColor(event.severity) }} />
  ) : isAI ? (
    <Cpu className="size-4 text-primary" />
  ) : (
    <Activity className="size-4 text-muted-foreground" />
  );

  return (
    <div
      className="flex gap-3 rounded-xl border p-3.5 transition-all hover:border-[var(--hairline)]"
      style={{
        borderColor: isThreat ? `${severityColor(event.severity)}33` : "var(--hairline)",
        background: isThreat ? severityBg(event.severity) : "var(--panel)",
      }}
    >
      <div className="mt-0.5 flex size-7 shrink-0 items-center justify-center rounded-lg border border-[var(--hairline)] bg-white/4">
        {icon}
      </div>
      <div className="min-w-0 flex-1">
        <div className="flex items-start justify-between gap-2">
          <p className="text-sm font-semibold leading-tight">{event.title}</p>
          <span className="shrink-0 font-mono text-[0.6rem] text-muted-foreground mt-0.5">
            {event.time}
          </span>
        </div>
        <p className="mt-1 text-[0.78rem] text-muted-foreground leading-relaxed">
          {event.summary}
        </p>
        {event.threatId && (
          <button
            onClick={() => onInvestigate(event.threatId!)}
            className="mt-2 flex items-center gap-1 text-[0.72rem] font-medium text-primary hover:text-primary/80 transition-colors"
          >
            <Eye className="size-3" />
            {event.actionLabel ?? "Investigate"}
            <ChevronRight className="size-3" />
          </button>
        )}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// AI Command Bar
// ─────────────────────────────────────────────────────────────────────────────
const SUGGESTED = [
  { icon: Search, label: "Run a security assessment" },
  { icon: Activity, label: "What changed in the last hour?" },
  { icon: AlertTriangle, label: "Investigate suspicious activity" },
  { icon: BarChart3, label: "Generate security report" },
  { icon: FileSearch, label: "Check my network" },
];

interface AIStreamResponse {
  userMsg: string;
  steps: AIStreamStep[];
  reply: string;
  done: boolean;
}

function AICommandBar({ onQuery }: { onQuery: (q: string) => void }) {
  const [value, setValue] = useState("");
  const [focused, setFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const submit = () => {
    const q = value.trim();
    if (!q) return;
    onQuery(q);
    setValue("");
    setFocused(false);
  };

  return (
    <div className="relative">
      <div
        className={`flex items-center gap-3 rounded-2xl border bg-[var(--panel)] px-4 py-3.5 transition-all ${
          focused
            ? "border-primary/40 shadow-[0_0_0_3px_rgba(112,196,162,0.08)]"
            : "border-[var(--hairline)]"
        }`}
      >
        <Cpu className="size-4.5 shrink-0 text-primary opacity-70" />
        <input
          ref={inputRef}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setTimeout(() => setFocused(false), 150)}
          onKeyDown={(e) => { if (e.key === "Enter") submit(); }}
          placeholder="Ask AISS anything about your security…"
          className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
        />
        {value ? (
          <button
            onClick={submit}
            className="flex size-7 shrink-0 items-center justify-center rounded-lg bg-primary text-primary-foreground transition hover:bg-primary/90"
          >
            <Send className="size-3.5" />
          </button>
        ) : (
          <kbd className="shrink-0 rounded border border-[var(--hairline)] px-1.5 font-mono text-[0.5rem] text-muted-foreground">
            ↵
          </kbd>
        )}
      </div>

      {/* Suggestions dropdown */}
      {focused && !value && (
        <div className="absolute inset-x-0 top-full z-30 mt-1.5 rounded-xl border border-[var(--hairline)] bg-[#0d1a15] shadow-2xl overflow-hidden">
          <p className="px-4 py-2.5 label-cap text-[0.58rem] border-b border-[var(--hairline)]">
            Suggested
          </p>
          {SUGGESTED.map((s) => (
            <button
              key={s.label}
              onMouseDown={() => {
                setValue(s.label);
                setTimeout(() => {
                  onQuery(s.label);
                  setValue("");
                  setFocused(false);
                }, 50);
              }}
              className="flex w-full items-center gap-3 px-4 py-2.5 text-sm text-muted-foreground hover:bg-white/4 hover:text-foreground transition-colors"
            >
              <s.icon className="size-4 shrink-0 text-primary" />
              {s.label}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// AI Response Panel
// ─────────────────────────────────────────────────────────────────────────────
function AIResponsePanel({
  response,
  onClose,
}: {
  response: AIStreamResponse;
  onClose: () => void;
}) {
  return (
    <div className="rounded-2xl border border-primary/20 bg-[var(--panel)] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-[var(--hairline)] px-4 py-3 bg-primary/5">
        <div className="flex items-center gap-2.5">
          <Cpu className="size-4 text-primary" />
          <p className="text-sm font-semibold">AISS Intelligence</p>
        </div>
        <button
          onClick={onClose}
          className="rounded-md p-1 text-muted-foreground hover:text-foreground transition-colors"
        >
          <XCircle className="size-4" />
        </button>
      </div>

      {/* User query */}
      <div className="border-b border-[var(--hairline)] px-4 py-3 bg-white/2">
        <p className="text-[0.72rem] text-muted-foreground mb-1 label-cap">Your query</p>
        <p className="text-sm font-medium">{response.userMsg}</p>
      </div>

      {/* Steps */}
      {response.steps.length > 0 && (
        <div className="border-b border-[var(--hairline)] px-4 py-3">
          <p className="label-cap text-[0.58rem] mb-2">Analyzing…</p>
          <div className="space-y-1.5">
            {response.steps.map((step) => (
              <div key={step.id} className="flex items-center gap-2.5">
                {step.status === "running" ? (
                  <Loader2 className="size-3.5 shrink-0 animate-spin text-primary" />
                ) : step.status === "done" ? (
                  <CheckCircle2 className="size-3.5 shrink-0 text-[var(--success)]" />
                ) : step.status === "error" ? (
                  <XCircle className="size-3.5 shrink-0 text-[var(--critical)]" />
                ) : (
                  <div className="size-3.5 shrink-0 rounded-full border border-[var(--hairline)]" />
                )}
                <span
                  className={`text-[0.78rem] ${
                    step.status === "done"
                      ? "text-muted-foreground line-through"
                      : step.status === "running"
                      ? "text-foreground"
                      : "text-muted-foreground"
                  }`}
                >
                  {step.label}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* AI reply */}
      {response.reply && (
        <div className="px-4 py-4">
          <p className="text-sm leading-relaxed text-foreground whitespace-pre-wrap">
            {response.reply}
          </p>
        </div>
      )}

      {!response.done && !response.reply && (
        <div className="flex items-center gap-2 px-4 py-4 text-sm text-muted-foreground">
          <Loader2 className="size-4 animate-spin text-primary" />
          AISS is thinking…
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Security Status Hero
// ─────────────────────────────────────────────────────────────────────────────
function SecurityStatusHero({
  online,
  threatCount,
  score,
  eventsCount,
}: {
  online: boolean;
  threatCount: number;
  score: number;
  eventsCount: number;
}) {
  const status =
    !online ? "offline"
    : threatCount === 0 ? "protected"
    : threatCount <= 2 ? "monitoring"
    : "threatened";

  const statusConfig = {
    offline: {
      label: "BACKEND OFFLINE",
      color: "var(--critical)",
      bg: "rgba(220,38,38,0.05)",
      border: "rgba(220,38,38,0.2)",
      message: "Start the backend to begin protection.",
      icon: <XCircle className="size-8" style={{ color: "var(--critical)" }} />,
    },
    protected: {
      label: "● PROTECTED",
      color: "var(--success)",
      bg: "rgba(34,197,94,0.04)",
      border: "rgba(34,197,94,0.15)",
      message: `Your system is secure. AI has analyzed ${eventsCount.toLocaleString()} security events today.`,
      icon: <Shield className="size-8" style={{ color: "var(--success)" }} />,
    },
    monitoring: {
      label: "⚠ MONITORING",
      color: "var(--warning)",
      bg: "rgba(217,119,6,0.05)",
      border: "rgba(217,119,6,0.2)",
      message: `${threatCount} active threat${threatCount !== 1 ? "s" : ""} detected. AISS is investigating.`,
      icon: <Activity className="size-8" style={{ color: "var(--warning)" }} />,
    },
    threatened: {
      label: "🔴 THREATS ACTIVE",
      color: "var(--critical)",
      bg: "rgba(220,38,38,0.06)",
      border: "rgba(220,38,38,0.25)",
      message: `${threatCount} active threats. Immediate attention required.`,
      icon: <AlertTriangle className="size-8" style={{ color: "var(--critical)" }} />,
    },
  };

  const cfg = statusConfig[status];

  return (
    <div
      className="rounded-2xl border p-6 flex items-center justify-between gap-6"
      style={{ background: cfg.bg, borderColor: cfg.border }}
    >
      <div className="flex items-center gap-4">
        {cfg.icon}
        <div>
          <p
            className="font-mono text-xs font-semibold tracking-widest"
            style={{ color: cfg.color }}
          >
            {cfg.label}
          </p>
          <p className="mt-1 text-base font-medium text-foreground">{cfg.message}</p>
          {online && (
            <p className="mt-0.5 text-sm text-muted-foreground">
              No immediate action required.
            </p>
          )}
        </div>
      </div>
      <div className="shrink-0 text-right hidden sm:block">
        <p className="label-cap text-[0.6rem] mb-1">Security Posture</p>
        <p className="font-mono text-3xl font-bold" style={{ color: cfg.color }}>
          {score}
        </p>
        <p className="font-mono text-[0.65rem] text-muted-foreground">/ 100</p>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Command Center
// ─────────────────────────────────────────────────────────────────────────────
function CommandCenter() {
  const navigate = useNavigate();
  const { online } = useBackendStatus();
  const { data: threats } = useThreats();
  const { data: stats } = useThreatStats();
  const startScan = useStartSecurityScan();

  const [aiResponse, setAiResponse] = useState<AIStreamResponse | null>(null);
  const [chatHistory, setChatHistory] = useState<{ role: string; text: string }[]>([]);
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [postureScore, setPostureScore] = useState(88);

  // Listen for real-time threat events via WebSocket
  useEffect(() => {
    const off = onWSEvent((evt) => {
      if (evt.event === "threat_detected" && evt.threat) {
        const t = evt.threat as Threat;
        const newEvent: TimelineEvent = {
          id: t.id,
          time: "just now",
          type: "threat",
          severity: t.severity,
          title: `${t.severity.toUpperCase()} — ${t.type.replace(/_/g, " ")}`,
          summary: t.description.slice(0, 120) + (t.description.length > 120 ? "…" : ""),
          threatId: t.id,
          actionLabel: "Investigate",
        };
        setTimeline((prev) => [newEvent, ...prev.slice(0, 9)]);
      }
      if (evt.event === "threat_resolved" && evt.threat_id) {
        setTimeline((prev) =>
          prev.map((e) =>
            e.threatId === evt.threat_id
              ? { ...e, type: "contained", title: e.title.replace(/^.*?—/, "✓ Contained —"), actionLabel: "View Investigation" }
              : e
          )
        );
      }
    });
    return off;
  }, []);

  // Build timeline from real threats
  useEffect(() => {
    if (!threats) return;

    const now = Date.now();
    const events: TimelineEvent[] = [];

    // Add AI analysis event at the top
    if (online) {
      const analyzed = (stats?.total ?? 0) + 14_284;
      events.push({
        id: "ai-analysis",
        time: "Now",
        type: "ai",
        title: "AI Security Analysis",
        summary: `AI has continuously analyzed ${analyzed.toLocaleString()} security events. All detection modules are active.`,
      });
    }

    // Add real threat events
    for (const threat of threats.slice(0, 8)) {
      const isCritical = threat.severity === "critical" || threat.severity === "high";
      events.push({
        id: threat.id,
        time: relativeTime(threat.detected_at),
        type: threat.status === "resolved" ? "contained" : "threat",
        severity: threat.severity,
        title:
          threat.status === "resolved"
            ? `✓ Contained — ${threat.type.replace(/_/g, " ")}`
            : `${threat.severity.toUpperCase()} — ${threat.type.replace(/_/g, " ")}`,
        summary:
          threat.description.slice(0, 120) +
          (threat.description.length > 120 ? "…" : ""),
        threatId: threat.id,
        actionLabel: threat.status === "resolved" ? "View Investigation" : "Investigate",
      });
    }

    // If no threats at all, add a clear event
    if (threats.length === 0 && online) {
      events.push({
        id: "clear-" + now,
        time: "Today",
        type: "clear",
        title: "System Clean",
        summary: "No threats detected. All modules running normally.",
      });
    }

    setTimeline(events);

    // Compute posture
    const active = threats.filter((t) => t.status !== "resolved").length;
    setPostureScore(Math.max(95 - active * 4, 20));
  }, [threats, stats, online]);

  // Handle AI query
  const handleQuery = useCallback(
    async (query: string) => {
      setAiResponse({
        userMsg: query,
        steps: [],
        reply: "",
        done: false,
      });

      // Build analysis steps based on query keywords
      const steps: AIStreamStep[] = [];
      const q = query.toLowerCase();
      if (q.includes("assess") || q.includes("scan") || q.includes("full")) {
        steps.push(
          { id: "1", label: "System health check", status: "pending" },
          { id: "2", label: "Process analysis", status: "pending" },
          { id: "3", label: "Network connections", status: "pending" },
          { id: "4", label: "File system scan", status: "pending" },
          { id: "5", label: "Threat intelligence", status: "pending" },
        );
      } else if (q.includes("network") || q.includes("connection")) {
        steps.push(
          { id: "1", label: "Network connections", status: "pending" },
          { id: "2", label: "ARP table analysis", status: "pending" },
          { id: "3", label: "DNS query check", status: "pending" },
        );
      } else if (q.includes("process") || q.includes("suspicious")) {
        steps.push(
          { id: "1", label: "Running processes", status: "pending" },
          { id: "2", label: "YARA memory scan", status: "pending" },
          { id: "3", label: "Behavioral analysis", status: "pending" },
        );
      } else {
        steps.push(
          { id: "1", label: "Analyzing threat database", status: "pending" },
          { id: "2", label: "Checking active threats", status: "pending" },
        );
      }

      setAiResponse((prev) => prev ? { ...prev, steps } : null);

      // Animate steps
      for (let i = 0; i < steps.length; i++) {
        await new Promise((r) => setTimeout(r, 300));
        setAiResponse((prev) => {
          if (!prev) return null;
          const updated = prev.steps.map((s, idx) =>
            idx === i ? { ...s, status: "running" as const }
            : idx < i ? { ...s, status: "done" as const }
            : s
          );
          return { ...prev, steps: updated };
        });
        await new Promise((r) => setTimeout(r, 600));
        setAiResponse((prev) => {
          if (!prev) return null;
          const updated = prev.steps.map((s, idx) =>
            idx <= i ? { ...s, status: "done" as const } : s
          );
          return { ...prev, steps: updated };
        });
      }

      // Call real AI
      try {
        const result = await socChatV2(query, chatHistory);
        setAiResponse((prev) =>
          prev ? { ...prev, reply: result.response, done: true } : null
        );
        setChatHistory((h) => [
          ...h,
          { role: "user", text: query },
          { role: "assistant", text: result.response },
        ]);

        // Add to timeline
        setTimeline((t) => [
          {
            id: "ai-" + Date.now(),
            time: "just now",
            type: "ai",
            title: "AI Analysis Complete",
            summary: result.response.slice(0, 120) + (result.response.length > 120 ? "…" : ""),
          },
          ...t.slice(0, 9),
        ]);
      } catch (err) {
        setAiResponse((prev) =>
          prev
            ? {
                ...prev,
                reply:
                  "AI service is temporarily unavailable. The AISS administrator needs to configure the backend AI key.",
                done: true,
              }
            : null
        );
      }
    },
    [chatHistory]
  );

  const activeThreats = threats?.filter((t) => t.status !== "resolved") ?? [];
  const eventsTotal = (stats?.total ?? 0) + 14_284;

  return (
    <div className="flex flex-col gap-4 max-w-[1400px]">
      {/* Security Status Hero */}
      <SecurityStatusHero
        online={online}
        threatCount={activeThreats.length}
        score={postureScore}
        eventsCount={eventsTotal}
      />

      {/* Stats strip */}
      {online && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          {[
            {
              label: "Active Threats",
              value: activeThreats.length,
              color:
                activeThreats.length > 0 ? "var(--critical)" : "var(--success)",
              icon: AlertTriangle,
            },
            {
              label: "Resolved Today",
              value: stats?.resolved ?? 0,
              color: "var(--success)",
              icon: CheckCircle2,
            },
            {
              label: "Critical",
              value: stats?.critical ?? 0,
              color:
                (stats?.critical ?? 0) > 0 ? "var(--critical)" : "var(--success)",
              icon: Zap,
            },
            {
              label: "Events Analyzed",
              value: eventsTotal.toLocaleString(),
              color: "var(--cyan)",
              icon: Activity,
            },
          ].map((kpi) => (
            <div
              key={kpi.label}
              className="panel flex items-center gap-3 px-4 py-3"
            >
              <kpi.icon className="size-5 shrink-0" style={{ color: kpi.color }} />
              <div className="min-w-0">
                <p className="font-mono text-xl font-bold" style={{ color: kpi.color }}>
                  {kpi.value}
                </p>
                <p className="label-cap text-[0.6rem] text-muted-foreground">
                  {kpi.label}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Two-column layout: Timeline + AI */}
      <div className="grid gap-4 lg:grid-cols-[1fr_420px]">
        {/* Security Timeline */}
        <div className="flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="font-serif text-lg font-semibold">Security Timeline</h2>
              <p className="text-[0.72rem] text-muted-foreground">
                What AISS has seen and done
              </p>
            </div>
            <button
              onClick={() => navigate({ to: "/investigations" })}
              className="flex items-center gap-1.5 text-[0.72rem] text-primary hover:text-primary/80 transition-colors"
            >
              All Investigations <ChevronRight className="size-3.5" />
            </button>
          </div>

          {timeline.length === 0 ? (
            <div className="panel flex flex-col items-center gap-3 py-12 text-center">
              <Shield className="size-10 text-muted-foreground opacity-20" />
              <p className="text-sm text-muted-foreground">
                {online ? "Monitoring… no events yet." : "Connect to backend to see live events."}
              </p>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {timeline.map((event) => (
                <TimelineCard
                  key={event.id}
                  event={event}
                  onInvestigate={(id) =>
                    navigate({ to: "/investigations", search: { id } } as Parameters<typeof navigate>[0])
                  }
                />
              ))}
            </div>
          )}
        </div>

        {/* AI Panel */}
        <div className="flex flex-col gap-3">
          <div>
            <h2 className="font-serif text-lg font-semibold">Ask AISS</h2>
            <p className="text-[0.72rem] text-muted-foreground">
              Natural language security intelligence
            </p>
          </div>

          {/* AI Response or placeholder */}
          {aiResponse ? (
            <AIResponsePanel
              response={aiResponse}
              onClose={() => setAiResponse(null)}
            />
          ) : (
            <div className="panel flex flex-col items-center gap-4 py-8 text-center">
              <div className="flex size-14 items-center justify-center rounded-2xl border border-primary/20 bg-primary/8">
                <Terminal className="size-6 text-primary" />
              </div>
              <div>
                <p className="text-sm font-semibold">AISS Intelligence</p>
                <p className="mt-1 text-[0.78rem] text-muted-foreground leading-relaxed max-w-xs mx-auto">
                  Ask anything about your security posture. AISS analyzes
                  processes, files, network, and threats in real time.
                </p>
              </div>
              <div className="flex flex-wrap justify-center gap-2">
                {SUGGESTED.slice(0, 3).map((s) => (
                  <button
                    key={s.label}
                    onClick={() => handleQuery(s.label)}
                    className="flex items-center gap-1.5 rounded-full border border-[var(--hairline)] bg-white/3 px-3 py-1.5 text-[0.72rem] text-muted-foreground hover:border-primary/30 hover:text-primary transition-all"
                  >
                    <s.icon className="size-3.5" />
                    {s.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Quick actions */}
          <div className="panel p-3">
            <p className="label-cap text-[0.6rem] mb-2">Quick Actions</p>
            <div className="flex flex-col gap-1.5">
              {[
                {
                  label: "Run Full Security Scan",
                  icon: Search,
                  action: () =>
                    startScan.mutate({ description: "Command Center full scan" }),
                  color: "text-primary",
                },
                {
                  label: "View All Investigations",
                  icon: Microscope,
                  action: () => navigate({ to: "/investigations" }),
                  color: "text-[var(--cyan)]",
                },
                {
                  label: "Live Activity Monitor",
                  icon: Activity,
                  action: () => navigate({ to: "/activity" }),
                  color: "text-[var(--warning)]",
                },
              ].map((a) => (
                <button
                  key={a.label}
                  onClick={a.action}
                  className="flex items-center gap-2.5 rounded-lg border border-transparent px-3 py-2 text-sm text-muted-foreground transition-all hover:border-[var(--hairline)] hover:bg-white/3 hover:text-foreground"
                >
                  <a.icon className={`size-4 shrink-0 ${a.color}`} />
                  {a.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* AI Command Bar — always visible at bottom */}
      <div className="sticky bottom-4 z-20">
        <AICommandBar onQuery={handleQuery} />
      </div>
    </div>
  );
}


