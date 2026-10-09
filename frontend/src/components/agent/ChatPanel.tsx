/**
 * ChatPanel — Agent conversation interface
 * Redesigned to match AISS design system.
 */
import { useRef, useEffect, useState, type KeyboardEvent } from "react";
import { Send, Bot, User, Loader2, Shield } from "lucide-react";
import type { ChatMessage } from "../../api/agentApi";

interface ChatPanelProps {
  messages:  ChatMessage[];
  isLoading: boolean;
  onMessage: (message: string) => void;
}

const QUICK_PROMPTS = [
  "Run a full security assessment",
  "What threats are active right now?",
  "Check system health",
  "Generate a weekly security report",
];

function formatTime(iso: string) {
  try { return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }
  catch { return ""; }
}

export function ChatPanel({ messages, isLoading, onMessage }: ChatPanelProps) {
  const [input,   setInput]   = useState("");
  const bottomRef             = useRef<HTMLDivElement>(null);
  const textareaRef           = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages, isLoading]);

  const handleSend = () => {
    const msg = input.trim();
    if (!msg || isLoading) return;
    setInput("");
    onMessage(msg);
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); }
  };

  return (
    <div className="flex h-full flex-col">
      {/* Message list */}
      <div
        role="log"
        aria-label="Agent conversation"
        aria-live="polite"
        className="flex-1 overflow-y-auto px-4 py-4 space-y-3"
      >
        {/* Empty state */}
        {messages.length === 0 && (
          <div className="flex flex-col items-center justify-center gap-4 py-16 text-center">
            <div className="flex size-14 items-center justify-center rounded-2xl border border-primary/20 bg-primary/8">
              <Shield className="size-7 text-primary" />
            </div>
            <div>
              <p className="font-serif text-base font-semibold">AISS Security Agent</p>
              <p className="mt-1 text-[0.78rem] text-muted-foreground max-w-xs leading-relaxed">
                Ask me to run security assessments, investigate threats,
                check vulnerabilities, or generate reports.
              </p>
            </div>
            {/* Quick prompts */}
            <div className="flex flex-wrap justify-center gap-2 mt-1">
              {QUICK_PROMPTS.map(q => (
                <button
                  key={q}
                  onClick={() => onMessage(q)}
                  disabled={isLoading}
                  className="rounded-full border border-[var(--hairline)] bg-white/3 px-3 py-1.5 text-[0.72rem] text-muted-foreground transition-all hover:border-primary/30 hover:bg-primary/8 hover:text-primary disabled:opacity-50"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Messages */}
        {messages.map((msg, i) => {
          const isUser   = msg.role === "user";
          const isSystem = msg.role === "system";

          if (isSystem) {
            return (
              <div key={i} className="flex justify-center">
                <div className="rounded-lg border border-[var(--warning)]/25 bg-[var(--warning)]/8 px-3 py-2 text-[0.72rem] text-[var(--warning)]">
                  {msg.content}
                </div>
              </div>
            );
          }

          return (
            <div key={i} className={`flex gap-2.5 ${isUser ? "flex-row-reverse" : ""}`}>
              {/* Avatar */}
              <div className={`flex size-7 shrink-0 items-center justify-center rounded-full border ${
                isUser
                  ? "border-[var(--hairline)] bg-white/6"
                  : "border-primary/20 bg-primary/10"
              }`}>
                {isUser
                  ? <User className="size-3.5 text-muted-foreground" />
                  : <Bot  className="size-3.5 text-primary" />
                }
              </div>

              {/* Bubble */}
              <div className={`max-w-[82%] min-w-0 rounded-2xl px-4 py-3 ${
                isUser
                  ? "rounded-tr-sm border border-primary/20 bg-primary/10 text-foreground"
                  : "rounded-tl-sm border border-[var(--hairline)] bg-[var(--panel)] text-foreground"
              }`}>
                <p className="text-sm leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                <p className="mt-1.5 font-mono text-[0.58rem] text-muted-foreground">
                  {formatTime(msg.created_at)}
                  {msg.task_id && (
                    <span className="ml-2 opacity-50">#{msg.task_id.slice(0, 8)}</span>
                  )}
                </p>
              </div>
            </div>
          );
        })}

        {/* Typing indicator */}
        {isLoading && (
          <div className="flex gap-2.5">
            <div className="flex size-7 shrink-0 items-center justify-center rounded-full border border-primary/20 bg-primary/10">
              <Bot className="size-3.5 text-primary" />
            </div>
            <div className="rounded-2xl rounded-tl-sm border border-[var(--hairline)] bg-[var(--panel)] px-4 py-3">
              <div className="flex items-center gap-1.5">
                <Loader2 className="size-3.5 animate-spin text-primary" />
                <span className="font-mono text-[0.65rem] text-muted-foreground">Analyzing…</span>
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Quick actions (only when chat started) */}
      {messages.length > 0 && (
        <div className="flex flex-wrap gap-1.5 border-t border-[var(--hairline)] bg-[var(--surface)]/80 px-4 py-2">
          {QUICK_PROMPTS.slice(0, 3).map(q => (
            <button
              key={q}
              onClick={() => onMessage(q)}
              disabled={isLoading}
              className="rounded-full border border-[var(--hairline)] bg-white/3 px-3 py-1 text-[0.65rem] text-muted-foreground transition-all hover:border-primary/30 hover:text-primary disabled:opacity-50"
            >
              {q}
            </button>
          ))}
        </div>
      )}

      {/* Input area */}
      <div className="border-t border-[var(--hairline)] bg-[var(--surface)]/80 p-3 flex gap-2.5 items-end">
        <textarea
          ref={textareaRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isLoading}
          placeholder="Ask the security agent anything… (Enter to send)"
          aria-label="Message to security agent"
          rows={2}
          maxLength={4096}
          className="flex-1 min-w-0 resize-none rounded-xl border border-[var(--hairline)] bg-white/4 px-3.5 py-2.5 text-sm text-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50 disabled:opacity-50"
        />
        <button
          onClick={handleSend}
          disabled={!input.trim() || isLoading}
          aria-label="Send message"
          className="flex size-10 shrink-0 items-center justify-center rounded-xl border border-primary/30 bg-primary/12 text-primary transition-all hover:bg-primary/22 disabled:opacity-40"
        >
          {isLoading
            ? <Loader2 className="size-4 animate-spin" />
            : <Send    className="size-4" />
          }
        </button>
      </div>
    </div>
  );
}
