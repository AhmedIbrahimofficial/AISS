"use client";
import { useState, useRef, useEffect } from "react";
import { MessageSquare, X, Send, Bot, User, Loader2 } from "lucide-react";


interface Message {
  role:    "user" | "assistant";
  content: string;
}

const SUGGESTED = [
  "Why is this alert dangerous?",
  "Show related CVEs",
  "Recommend mitigation steps",
  "Is this a false positive?",
  "How do I block this IP?",
];

export default function SocChat({ threatId = "" }: { threatId?: string }) {
  const [open,     setOpen]     = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    { role: "assistant", content: "👋 Hi! I'm your AI SOC Assistant. Ask me anything about threats, CVEs, or mitigations." }
  ]);
  const [input,    setInput]    = useState("");
  const [loading,  setLoading]  = useState(false);
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  async function send(text: string) {
    if (!text.trim() || loading) return;
    const userMsg = text.trim();
    setInput("");
    setMessages(prev => [...prev, { role: "user", content: userMsg }]);
    setLoading(true);

    try {
      const apiKey = process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY || "";
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000);
      const res = await fetch("http://localhost:8000/api/soc/chat", {
        method:  "POST",
        signal:  controller.signal,
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          message:   userMsg,
          threat_id: threatId,
          api_key:   apiKey,
        }),
      });
      clearTimeout(timeout);

      const data = await res.json();

      if (!res.ok) {
        throw new Error(data.detail || "Request failed");
      }

      setMessages(prev => [...prev, { role: "assistant", content: data.reply }]);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "";
      setMessages(prev => [...prev, {
        role:    "assistant",
        content: msg.includes("abort")
          ? "⚠️ Backend is offline. Start the server with `python main.py` and try again."
          : `⚠️ ${msg || "Error connecting to AI service. Make sure ANTHROPIC_API_KEY is set."}`
      }]);
    } finally {
      setLoading(false);
    }
  }

  return (
    <>
      {/* Toggle button */}
      <button
        onClick={() => setOpen(!open)}
        className="fixed bottom-6 right-6 z-50 w-14 h-14 rounded-full btn-neon-solid flex items-center justify-center shadow-lg"
        style={{ boxShadow: "0 0 24px rgba(0,255,136,0.4)" }}
        title="AI SOC Assistant"
      >
        {open ? <X size={22} /> : <MessageSquare size={22} />}
      </button>

      {/* Chat window */}
      {open && (
        <div className="fixed bottom-24 right-6 z-50 w-96 max-w-[calc(100vw-24px)] flex flex-col rounded-2xl overflow-hidden"
          style={{
            height: "520px",
            background: "rgba(0,0,0,0.95)",
            border: "1px solid rgba(0,255,136,0.2)",
            boxShadow: "0 0 40px rgba(0,255,136,0.1)",
          }}>

          {/* Header */}
          <div className="flex items-center gap-3 px-4 py-3 border-b border-white/10"
            style={{ background: "rgba(0,255,136,0.05)" }}>
            <div className="w-8 h-8 rounded-full bg-neon/20 border border-neon/30 flex items-center justify-center">
              <Bot size={16} className="text-neon" />
            </div>
            <div>
              <p className="text-white font-semibold text-sm">AI SOC Assistant</p>
              <p className="text-neon text-xs flex items-center gap-1">
                <span className="w-1.5 h-1.5 rounded-full bg-neon inline-block animate-pulse" />
                Online
              </p>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3">
            {messages.map((m, i) => (
              <div key={i} className={`flex gap-2 ${m.role === "user" ? "justify-end" : "justify-start"}`}>
                {m.role === "assistant" && (
                  <div className="w-6 h-6 rounded-full bg-neon/20 flex items-center justify-center shrink-0 mt-1">
                    <Bot size={12} className="text-neon" />
                  </div>
                )}
                <div
                  className="max-w-[80%] rounded-xl px-3 py-2 text-xs leading-relaxed whitespace-pre-wrap"
                  style={{
                    background: m.role === "user"
                      ? "rgba(0,255,136,0.15)"
                      : "rgba(255,255,255,0.05)",
                    border: m.role === "user"
                      ? "1px solid rgba(0,255,136,0.3)"
                      : "1px solid rgba(255,255,255,0.1)",
                    color: "#e0e0e0",
                  }}
                >
                  {m.content}
                </div>
                {m.role === "user" && (
                  <div className="w-6 h-6 rounded-full bg-white/10 flex items-center justify-center shrink-0 mt-1">
                    <User size={12} className="text-white/60" />
                  </div>
                )}
              </div>
            ))}

            {loading && (
              <div className="flex gap-2 justify-start">
                <div className="w-6 h-6 rounded-full bg-neon/20 flex items-center justify-center shrink-0">
                  <Bot size={12} className="text-neon" />
                </div>
                <div className="rounded-xl px-3 py-2 text-xs"
                  style={{ background: "rgba(255,255,255,0.05)", border: "1px solid rgba(255,255,255,0.1)" }}>
                  <Loader2 size={14} className="animate-spin text-neon" />
                </div>
              </div>
            )}
            <div ref={bottomRef} />
          </div>

          {/* Suggestions */}
          {messages.length <= 1 && (
            <div className="px-4 pb-2 flex flex-wrap gap-1">
              {SUGGESTED.map((s, i) => (
                <button key={i} onClick={() => send(s)}
                  className="text-xs px-2 py-1 rounded-full text-neon/70 hover:text-neon transition-colors"
                  style={{ background: "rgba(0,255,136,0.05)", border: "1px solid rgba(0,255,136,0.15)" }}>
                  {s}
                </button>
              ))}
            </div>
          )}

          {/* Input */}
          <div className="px-4 py-3 border-t border-white/10 flex gap-2">
            <input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && send(input)}
              placeholder="Ask about this threat..."
              className="flex-1 bg-white/5 border border-white/10 rounded-xl px-3 py-2 text-white text-xs placeholder:text-white/30 outline-none focus:border-neon/50 transition-colors"
            />
            <button
              onClick={() => send(input)}
              disabled={!input.trim() || loading}
              className="w-9 h-9 rounded-xl btn-neon-solid flex items-center justify-center disabled:opacity-40"
            >
              <Send size={14} />
            </button>
          </div>

        </div>
      )}
    </>
  );
}
