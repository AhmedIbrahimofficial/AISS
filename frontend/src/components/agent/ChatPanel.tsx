/**
 * ChatPanel — Agent conversation interface
 * Requirements: 1.1, 1.2
 */
import React, { useRef, useEffect, useState, KeyboardEvent } from "react";
import type { ChatMessage } from "../../api/agentApi";

interface ChatPanelProps {
  messages: ChatMessage[];
  isLoading: boolean;
  onMessage: (message: string) => void;
}

export function ChatPanel({ messages, isLoading, onMessage }: ChatPanelProps) {
  const [input, setInput] = useState("");
  const bottomRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom on new messages
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
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  const formatTime = (iso: string) => {
    try {
      return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    } catch {
      return "";
    }
  };

  return (
    <div className="flex flex-col h-full bg-gray-950 rounded-xl border border-gray-800 overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3 border-b border-gray-800 bg-gray-900 flex items-center gap-3">
        <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse" />
        <span className="text-sm font-semibold text-gray-200 tracking-wide">AISS Security Agent</span>
        <span className="ml-auto text-xs text-gray-500">AI-powered • Real data only</span>
      </div>

      {/* Message list */}
      <div
        role="log"
        aria-label="Agent conversation"
        aria-live="polite"
        className="flex-1 overflow-y-auto px-5 py-4 space-y-4 scrollbar-thin scrollbar-thumb-gray-700"
      >
        {messages.length === 0 && (
          <div className="text-center text-gray-500 text-sm mt-8">
            <div className="text-2xl mb-2">🛡️</div>
            <p className="font-medium text-gray-400">AISS Security Agent ready</p>
            <p className="text-xs mt-1">Ask me to run a security assessment, check vulnerabilities,<br />investigate threats, or generate a report.</p>
          </div>
        )}

        {messages.map((msg, i) => (
          <div
            key={i}
            className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
          >
            {msg.role !== "user" && (
              <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-xs font-bold text-white mr-2 mt-1 shrink-0">AI</div>
            )}
            <div
              className={`max-w-[80%] rounded-2xl px-4 py-2.5 text-sm leading-relaxed ${
                msg.role === "user"
                  ? "bg-blue-600 text-white rounded-br-sm"
                  : msg.role === "system"
                  ? "bg-yellow-900/40 border border-yellow-700 text-yellow-200"
                  : "bg-gray-800 text-gray-100 rounded-bl-sm"
              }`}
            >
              <p className="whitespace-pre-wrap">{msg.content}</p>
              <p className={`text-xs mt-1 ${msg.role === "user" ? "text-blue-200" : "text-gray-500"}`}>
                {formatTime(msg.created_at)}
                {msg.task_id && <span className="ml-2 opacity-60">#{msg.task_id.slice(0, 8)}</span>}
              </p>
            </div>
          </div>
        ))}

        {/* Typing indicator */}
        {isLoading && (
          <div className="flex justify-start">
            <div className="w-7 h-7 rounded-full bg-blue-600 flex items-center justify-center text-xs font-bold text-white mr-2 mt-1 shrink-0">AI</div>
            <div className="bg-gray-800 rounded-2xl rounded-bl-sm px-4 py-3">
              <div className="flex gap-1 items-center">
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
                <div className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
              </div>
            </div>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Quick actions */}
      <div className="px-4 pt-2 flex gap-2 flex-wrap border-t border-gray-800/50">
        {[
          "Run full security assessment",
          "Check vulnerabilities",
          "Generate weekly report",
          "Show connected devices",
        ].map((q) => (
          <button
            key={q}
            onClick={() => onMessage(q)}
            disabled={isLoading}
            className="text-xs px-3 py-1 rounded-full bg-gray-800 text-gray-300 hover:bg-gray-700 hover:text-white transition-colors disabled:opacity-50"
          >
            {q}
          </button>
        ))}
      </div>

      {/* Input area */}
      <div className="p-4 border-t border-gray-800 flex gap-3 items-end">
        <textarea
          ref={textareaRef}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={isLoading}
          placeholder="Ask the security agent anything... (Enter to send)"
          aria-label="Message to security agent"
          rows={2}
          className="flex-1 resize-none bg-gray-800 text-gray-100 text-sm rounded-xl px-4 py-2.5 border border-gray-700 focus:outline-none focus:border-blue-500 placeholder-gray-500 disabled:opacity-50 scrollbar-thin"
          maxLength={4096}
        />
        <button
          onClick={handleSend}
          disabled={!input.trim() || isLoading}
          aria-label="Send message"
          className="w-10 h-10 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:bg-gray-700 disabled:text-gray-500 text-white flex items-center justify-center transition-colors shrink-0"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M2.01 21L23 12 2.01 3 2 10l15 2-15 2z" />
          </svg>
        </button>
      </div>
    </div>
  );
}
