import { createFileRoute } from "@tanstack/react-router";
import { useRef, useState } from "react";
import { toast } from "sonner";
import { Send, Bot, User, Loader2, Sparkles } from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge, Metric } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { useSOCChat, useLLMProviders } from "@/hooks/useAISS";
import { extractIOCs, analyzePhishing, semanticSearch } from "@/lib/api";
import { ModulePage } from "@/components/soc/module";
import { MODULES } from "@/components/soc/modules";

export const Route = createFileRoute("/ai-assistant")({
  head: () => ({
    meta: [
      { title: "AI Assistant — AISS Security Operations" },
      { name: "description", content: "Live AI security analyst powered by AISS backend" },
    ],
  }),
  component: AIAssistantPage,
});

function AIAssistantPage() {
  const { messages, loading, send } = useSOCChat();
  const { data: llmData }          = useLLMProviders();
  const [input, setInput]          = useState("");
  const [iocText, setIocText]      = useState("");
  const [iocResult, setIocResult]  = useState<Record<string, string[]> | null>(null);
  const [urlInput, setUrlInput]    = useState("");
  const [phishResult, setPhishResult] = useState<{ risk_level: string; risk_score: number; flags: string[]; recommendation: string } | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<Array<{ document: string; score: number; metadata: { severity: string } }> | null>(null);
  const bottomRef = useRef<HTMLDivElement>(null);

  const handleSend = async () => {
    if (!input.trim()) return;
    const q = input.trim();
    setInput("");
    await send(q);
    setTimeout(() => bottomRef.current?.scrollIntoView({ behavior: "smooth" }), 100);
  };

  const handleIOCExtract = async () => {
    if (!iocText.trim()) return;
    try {
      const r = await extractIOCs(iocText);
      setIocResult(r.iocs as unknown as Record<string, string[]>);
      toast.success("IOCs extracted");
    } catch (e) { toast.error(String(e)); }
  };

  const handlePhishingCheck = async () => {
    if (!urlInput.trim()) return;
    try {
      const r = await analyzePhishing(urlInput.trim());
      setPhishResult(r);
      toast.success(`Phishing analysis: ${r.risk_level.toUpperCase()}`);
    } catch (e) { toast.error(String(e)); }
  };

  const handleSemanticSearch = async () => {
    if (!searchQuery.trim()) return;
    try {
      const r = await semanticSearch(searchQuery, 5);
      setSearchResults(r.results);
      toast.success(`${r.count} similar threats found`);
    } catch (e) { toast.error(String(e)); }
  };

  const providerText = llmData?.providers?.join(", ") ?? "No providers configured";

  return (
    <div>
      <PageHeader
        title="AI Assistant"
        subtitle="Live AI analyst — SOC chat, IOC extraction, phishing analysis, semantic threat search"
        right={
          <Badge tone={llmData?.total_providers ? "success" : "warning"}>
            {llmData?.total_providers ? providerText : "No LLM providers — add API keys in Settings"}
          </Badge>
        }
      />

      {!llmData?.total_providers && <ModulePage m={MODULES["ai-assistant"]!} />}

      {llmData?.total_providers ? (
        <div className="grid gap-3 xl:grid-cols-12">
          {/* SOC Chat */}
          <div className="xl:col-span-7">
            <Panel title="SOC Chat — Live AI Analyst" right={<span className="dot-pulse size-2 bg-[var(--success)] text-[var(--success)]" />}>
              <div className="flex h-[420px] flex-col gap-3">
                <div className="flex-1 overflow-y-auto space-y-3 pr-1">
                  {messages.length === 0 && (
                    <div className="flex h-full flex-col items-center justify-center gap-3 text-muted-foreground">
                      <Sparkles className="size-10 opacity-30" />
                      <p className="text-sm">Ask anything about your security posture</p>
                      <div className="flex flex-wrap justify-center gap-2">
                        {["Summarize recent critical threats", "What MITRE techniques are active?", "Explain the latest C2 detection", "Draft an incident report"].map((s) => (
                          <button
                            key={s}
                            onClick={() => { setInput(s); }}
                            className="rounded-md border border-[var(--hairline)] px-2.5 py-1 text-xs hover:border-primary/40 hover:text-primary"
                          >
                            {s}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                  {messages.map((m, i) => (
                    <div key={i} className={`flex gap-2.5 ${m.role === "user" ? "flex-row-reverse" : ""}`}>
                      <div className="grid size-7 shrink-0 place-items-center rounded-full border border-[var(--hairline)] bg-white/4">
                        {m.role === "ai" ? <Bot className="size-4 text-primary" /> : <User className="size-4" />}
                      </div>
                      <div className={`max-w-[80%] rounded-lg border px-3 py-2 text-sm leading-relaxed ${
                        m.role === "user"
                          ? "border-primary/20 bg-primary/10 text-foreground"
                          : "border-[var(--hairline)] bg-white/3 text-muted-foreground"
                      }`}>
                        {m.text}
                      </div>
                    </div>
                  ))}
                  {loading && (
                    <div className="flex gap-2.5">
                      <div className="grid size-7 shrink-0 place-items-center rounded-full border border-[var(--hairline)] bg-white/4">
                        <Bot className="size-4 text-primary" />
                      </div>
                      <div className="flex items-center gap-2 rounded-lg border border-[var(--hairline)] bg-white/3 px-3 py-2">
                        <Loader2 className="size-4 animate-spin text-primary" />
                        <span className="text-xs text-muted-foreground">Analyzing…</span>
                      </div>
                    </div>
                  )}
                  <div ref={bottomRef} />
                </div>
                <div className="flex gap-2">
                  <input
                    className="flex-1 rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 text-sm outline-none placeholder:text-muted-foreground focus:border-primary/50"
                    placeholder="Ask the AI analyst…"
                    value={input}
                    onChange={(e) => setInput(e.target.value)}
                    onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); void handleSend(); } }}
                    disabled={loading}
                  />
                  <button
                    onClick={() => void handleSend()}
                    disabled={loading || !input.trim()}
                    className="grid size-10 shrink-0 place-items-center rounded-md bg-primary/20 border border-primary/40 text-primary hover:bg-primary/30 disabled:opacity-40"
                  >
                    <Send className="size-4" />
                  </button>
                </div>
              </div>
            </Panel>
          </div>

          {/* Tools panel */}
          <div className="flex flex-col gap-3 xl:col-span-5">
            {/* IOC Extractor */}
            <Panel title="IOC Extractor" right={<Badge tone="info">ioc-finder + spaCy</Badge>}>
              <textarea
                className="w-full rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 text-xs text-muted-foreground outline-none placeholder:text-muted-foreground focus:border-primary/50 resize-none"
                rows={3}
                placeholder="Paste any text, log line, or alert description…"
                value={iocText}
                onChange={(e) => setIocText(e.target.value)}
              />
              <ActionButton label="Extract IOCs" tone="info" className="mt-2" onClick={() => void handleIOCExtract()} />
              {iocResult && (
                <div className="mt-2 space-y-1">
                  {(["ips", "domains", "hashes", "cves", "malware_names", "mitre_techniques"] as const).map((k) => {
                    const vals = iocResult[k as keyof typeof iocResult] ?? [];
                    if (!vals.length) return null;
                    return (
                      <div key={k}>
                        <span className="label-cap text-[0.55rem]">{k.replace(/_/g, " ")}</span>
                        <div className="mt-0.5 flex flex-wrap gap-1">
                          {vals.slice(0, 6).map((v: string) => (
                            <span key={v} className="rounded border border-[var(--hairline)] bg-white/5 px-1.5 py-0.5 font-mono text-[0.6rem]">{v}</span>
                          ))}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </Panel>

            {/* Phishing Analyzer */}
            <Panel title="Phishing URL Analyzer" right={<Badge tone="warning">multi-layer</Badge>}>
              <div className="flex gap-2">
                <input
                  className="flex-1 rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 text-xs outline-none placeholder:text-muted-foreground focus:border-primary/50"
                  placeholder="https://suspicious-url.tk/login"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                />
                <ActionButton label="Analyze" tone="warning" onClick={() => void handlePhishingCheck()} />
              </div>
              {phishResult && (
                <div className="mt-2 space-y-2">
                  <div className="grid grid-cols-2 gap-2">
                    <Metric label="Risk Score" value={phishResult.risk_score.toFixed(0)} tone={phishResult.risk_level === "critical" ? "critical" : phishResult.risk_level === "high" ? "warning" : "info"} />
                    <Metric label="Risk Level" value={phishResult.risk_level.toUpperCase()} tone={phishResult.risk_level === "low" ? "success" : "warning"} />
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {phishResult.flags.map((f: string) => (
                      <Badge key={f} tone="warning">{f}</Badge>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">{phishResult.recommendation}</p>
                </div>
              )}
            </Panel>

            {/* Semantic Threat Search */}
            <Panel title="Semantic Threat Search" right={<Badge tone="info">ChromaDB</Badge>}>
              <div className="flex gap-2">
                <input
                  className="flex-1 rounded-md border border-[var(--hairline)] bg-white/5 px-3 py-2 text-xs outline-none placeholder:text-muted-foreground focus:border-primary/50"
                  placeholder="Find threats similar to: ransomware C2 beacon"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") void handleSemanticSearch(); }}
                />
                <ActionButton label="Search" tone="info" onClick={() => void handleSemanticSearch()} />
              </div>
              {searchResults && (
                <ul className="mt-2 space-y-1.5">
                  {searchResults.map((r, i) => (
                    <li key={i} className="rounded-md border border-[var(--hairline)] px-2.5 py-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <span className="truncate text-xs">{r.document.slice(0, 80)}</span>
                        <span className="font-mono text-[0.6rem] text-muted-foreground">{(r.score * 100).toFixed(0)}%</span>
                      </div>
                      <Badge tone={r.metadata?.severity === "critical" ? "critical" : "warning"} >{r.metadata?.severity}</Badge>
                    </li>
                  ))}
                </ul>
              )}
            </Panel>
          </div>
        </div>
      ) : null}
    </div>
  );
}
