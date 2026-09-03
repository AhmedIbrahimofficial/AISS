/**
 * AI Console — AISS
 * ChatGPT-style landing page: conversational AI that can execute security operations.
 * Powered by OpenRouter via SOCAgent with tool-calling.
 */
import { createFileRoute } from "@tanstack/react-router";
import { useRef, useEffect, type KeyboardEvent } from "react";
import { toast } from "sonner";
import {
  Shield, Send, Loader2, Bot, User, Sparkles,
  ScanLine, AlertTriangle, Activity, Globe2, Trash2,
} from "lucide-react";
import { useAIConsole } from "@/hooks/useAISS";
import { Badge } from "@/components/soc/ui";

export const Route = createFileRoute("/ai-console")({
  head: () => ({
    meta: [
      { title: "AISS AI Console" },
      { name: "description", content: "AI-powered security operations console — ask anything, execute anything" },
    ],
  }),
  component: AIConsolePage,
});

const EXAMPLE_PROMPTS = [
  { icon: ScanLine,       text: "Run a full security scan",          hint: "Scans files, network, IOCs" },
  { icon: AlertTriangle,  text: "What threats are active?",          hint: "Real-time threat overview" },
  { icon: Activity,       text: "Check system health",               hint: "CPU, memory, services" },
  { icon: Globe2,         text: "Enrich IP 8.8.8.8",                 hint: "VirusTotal + Shodan intel" },
  { icon: Shield,         text: "Verify detection pipeline",         hint: "EICAR test verification" },
  { icon: ScanLine,       text: "Run Nuclei vulnerability scan",     hint: "CVE/CVSS scoring" },
];

// Tool call → link mapping
const TOOL_LINKS: Record<string, { to: string; label: string }> = {
  run_scan:         { to: "/jobs",               label: "View in Jobs" },
  verify_pipeline:  { to: "/jobs",               label: "View Results" },
  get_threats:      { to: "/threats",            label: "View Threats" },
  get_threat_stats: { to: "/threats",            label: "View Threats" },
  resolve_threat:   { to: "/incidents",          label: "View Incidents" },
  enrich_ip:        { to: "/threat-intelligence", label: "View Intel" },
  get_system_health:{ to: "/system-health",      label: "System Health" },
  get_scan_tasks:   { to: "/jobs",               label: "View Jobs" },
  get_kill_chain:   { to: "/threats",            label: "View Threats" },
  block_ip:         { to: "/security-gateway",   label: "View Gateway" },
  run_nuclei_scan:  { to: "/vulnerability-scanner", label: "View Scanner" },
};

function ToolCallCard({ tc }: { tc: { tool: string; args: Record<string, unknown>; result: Record<string, unknown> } }) {
  const link = TOOL_LINKS[tc.tool];
  const isError = "error" in tc.result;
  return (
    <div className={`my-2 rounded-lg border px-3 py-2 ${
      isError ? "border-[var(--critical)]/30 bg-[var(--critical)]/5" : "border-primary/25 bg-primary/5"
    }`}>
      <div className="flex items-center gap-2 mb-1">
        <Sparkles className="size-3.5 text-primary" />
        <span className="font-mono text-[0.6rem] text-primary font-semibold uppercase tracking-wider">
          {tc.tool.replace(/_/g, " ")}
        </span>
        {isError
          ? <Badge tone="critical">FAILED</Badge>
          : <Badge tone="success">EXECUTED</Badge>
        }
      </div>
      {Object.keys(tc.args).length > 0 && (
        <p className="font-mono text-[0.58rem] text-muted-foreground mb-1">
          {Object.entries(tc.args).map(([k, v]) => `${k}: ${String(v)}`).join(", ")}
        </p>
      )}
      {!isError && link && (
        <a
          href={link.to}
          className="inline-flex items-center gap-1 font-mono text-[0.6rem] text-primary hover:underline mt-0.5"
        >
          {link.label} →
        </a>
      )}
    </div>
  );
}

function AIConsolePage() {
  const { messages, loading, send, clear } = useAIConsole();
  const inputRef  = useRef<HTMLInputElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);
  const hasStarted = messages.length > 0;

  // Auto-scroll on new messages
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSend = () => {
    const val = inputRef.current?.value.trim();
    if (!val || loading) return;
    void send(val);
    if (inputRef.current) inputRef.current.value = "";
  };

  const onKey = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); }
  };

  const handlePromptClick = (text: string) => {
    if (loading) return;
    void send(text);
  };

  return (
    <div className="flex min-h-[calc(100vh-8rem)] flex-col">
      {/* Welcome screen — shown when no messages */}
      {!hasStarted && (
        <div className="flex flex-1 flex-col items-center justify-center px-4 py-12">
          <div className="mb-6 grid size-16 place-items-center rounded-2xl border border-primary/30 bg-primary/8">
            <Shield className="size-8 text-primary" />
          </div>
          <h1 className="font-serif text-3xl font-bold mb-2">AISS Security Assistant</h1>
          <p className="text-sm text-muted-foreground mb-8 max-w-md text-center">
            Ask anything about your security posture, or command the AI to run scans,
            enrich indicators, manage incidents, and more.
          </p>
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3 max-w-2xl w-full">
            {EXAMPLE_PROMPTS.map((p) => (
              <button
                key={p.text}
                type="button"
                onClick={() => handlePromptClick(p.text)}
                className="flex items-start gap-3 rounded-lg border border-[var(--hairline)] bg-white/3 p-3 text-left transition-colors hover:border-primary/30 hover:bg-primary/5"
              >
                <p.icon className="size-4 shrink-0 mt-0.5 text-primary" />
                <div>
                  <p className="text-sm font-medium">{p.text}</p>
                  <p className="text-[0.65rem] text-muted-foreground mt-0.5">{p.hint}</p>
                </div>
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Chat messages */}
      {hasStarted && (
        <div className="flex-1 overflow-y-auto px-4 py-4 space-y-4 max-w-3xl w-full mx-auto">
          {/* Header bar */}
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Shield className="size-4 text-primary" />
              <span className="font-serif text-sm font-bold">AISS AI Console</span>
              <Badge tone="info">OpenRouter</Badge>
            </div>
            <button
              type="button"
              onClick={clear}
              className="flex items-center gap-1.5 rounded-md border border-[var(--hairline)] bg-white/3 px-2 py-1 font-mono text-[0.58rem] text-muted-foreground hover:text-foreground transition-colors"
            >
              <Trash2 className="size-3" />
              Clear
            </button>
          </div>

          {messages.map((m, i) => (
            <div key={i} className={`flex gap-3 ${m.role === "user" ? "flex-row-reverse" : ""}`}>
              <div
                className="grid size-8 shrink-0 place-items-center rounded-full border border-[var(--hairline)]"
                style={{
                  background: m.role === "ai" ? "rgba(59,130,246,0.12)" : "rgba(255,255,255,0.06)",
                }}
              >
                {m.role === "ai"
                  ? <Bot className="size-4 text-[var(--cyan)]" />
                  : <User className="size-4 text-muted-foreground" />
                }
              </div>
              <div className="max-w-[85%] min-w-0">
                <div
                  className="rounded-xl px-4 py-3"
                  style={{
                    background: m.role === "ai"
                      ? "rgba(59,130,246,0.06)"
                      : "rgba(255,255,255,0.04)",
                    border: `1px solid ${m.role === "ai" ? "rgba(59,130,246,0.18)" : "rgba(255,255,255,0.07)"}`,
                  }}
                >
                  <p className="text-sm leading-relaxed whitespace-pre-wrap">{m.text}</p>
                </div>
                {/* Tool call cards */}
                {m.tool_calls && m.tool_calls.length > 0 && (
                  <div className="mt-1">
                    {m.tool_calls.map((tc, j) => (
                      <ToolCallCard key={j} tc={tc} />
                    ))}
                  </div>
                )}
              </div>
            </div>
          ))}

          {/* Loading indicator */}
          {loading && (
            <div className="flex gap-3">
              <div
                className="grid size-8 shrink-0 place-items-center rounded-full border border-[var(--hairline)]"
                style={{ background: "rgba(59,130,246,0.12)" }}
              >
                <Bot className="size-4 text-[var(--cyan)]" />
              </div>
              <div className="rounded-xl border border-[rgba(59,130,246,0.18)] bg-[rgba(59,130,246,0.06)] px-4 py-3">
                <div className="flex items-center gap-2">
                  <Loader2 className="size-4 animate-spin text-[var(--cyan)]" />
                  <span className="font-mono text-xs text-muted-foreground">Thinking...</span>
                </div>
              </div>
            </div>
          )}
          <div ref={bottomRef} />
        </div>
      )}

      {/* Input bar — always visible at bottom */}
      <div className="sticky bottom-0 border-t border-[var(--hairline)] bg-[var(--surface)]/95 backdrop-blur px-4 py-3">
        <div className="mx-auto flex max-w-3xl gap-2">
          <input
            ref={inputRef}
            onKeyDown={onKey}
            placeholder="Ask the AI analyst anything... (e.g., 'Run a security scan', 'What threats are active?')"
            disabled={loading}
            className="flex-1 min-w-0 rounded-lg border border-[var(--hairline)] bg-white/5 px-4 py-2.5 text-sm outline-none placeholder:text-muted-foreground focus:border-primary/50 disabled:opacity-50"
          />
          <button
            type="button"
            onClick={handleSend}
            disabled={loading}
            className="grid size-10 shrink-0 place-items-center rounded-lg border border-primary/30 bg-primary/10 text-primary transition-colors hover:bg-primary/20 disabled:opacity-50"
          >
            {loading ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
          </button>
        </div>
        <p className="mx-auto max-w-3xl mt-1.5 font-mono text-[0.55rem] text-muted-foreground text-center">
          AISS AI can execute security operations. Powered by OpenRouter.
        </p>
      </div>
    </div>
  );
}
