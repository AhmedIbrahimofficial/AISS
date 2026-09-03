/**
 * SOC AI Chat Panel
 * Compact widget version of the AI Console for the dashboard.
 * Uses socChat via useSOCChat hook (calls /api/soc-chat).
 */
import { useRef, useEffect, KeyboardEvent } from "react";
import { Panel } from "./Panel";
import { Badge } from "./ui";
import { useSOCChat } from "@/hooks/useAISS";
import { Bot, User, Send, Loader2, MessageSquare } from "lucide-react";
import { Link } from "@tanstack/react-router";

const PROMPTS = [
  "Summarise active threats",
  "What's the highest risk right now?",
  "Any lateral movement detected?",
  "Suggest containment steps",
];

export function SocChatPanel() {
  const { messages, loading, send } = useSOCChat();
  const inputRef  = useRef<HTMLInputElement>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  // Auto-scroll
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

  return (
    <Panel
      title="SOC AI Assistant"
      right={
        <div className="flex items-center gap-2">
          <Badge tone="info">OpenRouter</Badge>
          <Link to="/ai-console" className="font-mono text-[0.6rem] text-primary hover:underline">
            FULL CONSOLE →
          </Link>
        </div>
      }
      bodyClassName="flex flex-col gap-2"
    >
      {/* Quick prompts */}
      <div className="flex flex-wrap gap-1">
        {PROMPTS.map((p) => (
          <button
            key={p}
            type="button"
            onClick={() => void send(p)}
            className="rounded border border-[var(--hairline)] px-2 py-0.5 font-mono text-[0.55rem] text-muted-foreground hover:border-primary/40 hover:text-primary transition-colors"
          >
            {p}
          </button>
        ))}
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-2 max-h-[220px] pr-1 min-h-[120px]">
        {messages.length === 0 && (
          <p className="text-center text-xs text-muted-foreground py-4">
            Ask the AI assistant anything about your security posture
          </p>
        )}
        {messages.map((m, i) => (
          <div
            key={i}
            className={`flex gap-2 ${m.role === "user" ? "flex-row-reverse" : ""}`}
          >
            <div
              className="grid size-6 shrink-0 place-items-center rounded-full border border-[var(--hairline)]"
              style={{ background: m.role === "ai" ? "rgba(59,130,246,0.12)" : "rgba(255,255,255,0.06)" }}
            >
              {m.role === "ai"
                ? <Bot className="size-3.5 text-[var(--cyan)]" />
                : <User className="size-3.5 text-muted-foreground" />
              }
            </div>
            <div
              className="max-w-[85%] rounded-lg px-2.5 py-1.5"
              style={{
                background: m.role === "ai"
                  ? "rgba(59,130,246,0.08)"
                  : "rgba(255,255,255,0.05)",
                border: `1px solid ${m.role === "ai" ? "rgba(59,130,246,0.2)" : "rgba(255,255,255,0.08)"}`,
              }}
            >
              <p className="text-xs leading-relaxed text-foreground whitespace-pre-wrap">{m.text}</p>
            </div>
          </div>
        ))}
        {loading && (
          <div className="flex gap-2">
            <div className="grid size-6 shrink-0 place-items-center rounded-full border border-[var(--hairline)] bg-[rgba(59,130,246,0.12)]">
              <Bot className="size-3.5 text-[var(--cyan)]" />
            </div>
            <div className="rounded-lg border border-[rgba(59,130,246,0.2)] bg-[rgba(59,130,246,0.08)] px-3 py-2">
              <Loader2 className="size-3.5 animate-spin text-[var(--cyan)]" />
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div className="flex gap-2 border-t border-[var(--hairline)] pt-2">
        <input
          ref={inputRef}
          onKeyDown={onKey}
          placeholder="Ask the AI analyst…"
          disabled={loading}
          className="flex-1 min-w-0 rounded-md border border-[var(--hairline)] bg-white/5 px-2.5 py-1.5 text-xs outline-none placeholder:text-muted-foreground focus:border-primary/50 disabled:opacity-50"
        />
        <button
          type="button"
          onClick={handleSend}
          disabled={loading}
          className="grid size-8 shrink-0 place-items-center rounded-md border border-[var(--hairline)] bg-white/5 text-muted-foreground transition-colors hover:border-primary/40 hover:text-primary disabled:opacity-50"
        >
          {loading ? <Loader2 className="size-3.5 animate-spin" /> : <Send className="size-3.5" />}
        </button>
      </div>
    </Panel>
  );
}
