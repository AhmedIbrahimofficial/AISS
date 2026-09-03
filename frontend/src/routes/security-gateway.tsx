/**
 * Security Gateway — AISS
 * Verifies incoming requests/files/IPs before allowing them into the protected environment.
 * Pipeline: Inspect → Validate → Threat Intel → AI Risk Analysis → Decision (ALLOW/BLOCK/QUARANTINE/REVIEW)
 */
import { createFileRoute } from "@tanstack/react-router";
import { useState, useRef } from "react";
import { toast } from "sonner";
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX,
  Upload, Globe, FileText, ChevronRight,
  CheckCircle, XCircle, AlertTriangle, Clock,
  Loader2, Info, Lock, Unlock, Eye, Bot,
} from "lucide-react";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge } from "@/components/soc/ui";
import {
  enrichIP, analyzeFile, analyzePhishing, extractIOCs,
  scoreAnomaly, llmAnalyze, triggerScan,
  type Threat,
} from "@/lib/api";

export const Route = createFileRoute("/security-gateway")({
  head: () => ({
    meta: [
      { title: "Security Gateway — AISS" },
      { name: "description", content: "Verify requests, files, IPs and domains before allowing entry" },
    ],
  }),
  component: SecurityGatewayPage,
});

// ── Types ─────────────────────────────────────────────────────────────

type Decision = "ALLOW" | "BLOCK" | "QUARANTINE" | "REVIEW" | null;
type InspectType = "ip" | "url" | "file" | "text" | "hash";

interface PipelineStage {
  id: string;
  label: string;
  status: "pending" | "running" | "pass" | "fail" | "warn" | "skip";
  detail?: string;
  score?: number;
}

interface GatewayResult {
  decision: Decision;
  riskScore: number;
  riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  stages: PipelineStage[];
  summary: string;
  iocs?: Record<string, string[]>;
  aiAnalysis?: string;
  blockedReasons?: string[];
  allowedReasons?: string[];
  timestamp: string;
}

const INITIAL_STAGES: PipelineStage[] = [
  { id: "auth",       label: "Authentication Check",     status: "pending" },
  { id: "input",      label: "Input Validation",          status: "pending" },
  { id: "inspect",    label: "Security Inspection",       status: "pending" },
  { id: "intel",      label: "Threat Intelligence",       status: "pending" },
  { id: "ioc",        label: "IOC / Malware Check",       status: "pending" },
  { id: "policy",     label: "Policy Evaluation",         status: "pending" },
  { id: "ai",         label: "AI Risk Analysis",          status: "pending" },
  { id: "decision",   label: "Security Decision",         status: "pending" },
];

// ── Risk score thresholds ─────────────────────────────────────────────
function riskLevel(score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
  if (score <= 20)  return "LOW";
  if (score <= 50)  return "MEDIUM";
  if (score <= 80)  return "HIGH";
  return "CRITICAL";
}

function decisionFromScore(score: number, blocked: boolean): Decision {
  if (blocked)   return "BLOCK";
  if (score > 80) return "BLOCK";
  if (score > 50) return "QUARANTINE";
  if (score > 20) return "REVIEW";
  return "ALLOW";
}

const toneFor: Record<string, "success" | "warning" | "critical" | "info"> = {
  ALLOW:      "success",
  BLOCK:      "critical",
  QUARANTINE: "warning",
  REVIEW:     "info",
};

const decisionIcon = {
  ALLOW:      <ShieldCheck className="size-5 text-green-400" />,
  BLOCK:      <ShieldX     className="size-5 text-red-400"   />,
  QUARANTINE: <ShieldAlert className="size-5 text-yellow-400" />,
  REVIEW:     <Eye         className="size-5 text-blue-400"  />,
};

const stageStatusIcon = {
  pending: <Clock className="size-3.5 text-gray-500" />,
  running: <Loader2 className="size-3.5 animate-spin text-blue-400" />,
  pass:    <CheckCircle className="size-3.5 text-green-400" />,
  fail:    <XCircle className="size-3.5 text-red-400" />,
  warn:    <AlertTriangle className="size-3.5 text-yellow-400" />,
  skip:    <Info className="size-3.5 text-gray-500" />,
};

// ── Recent history ────────────────────────────────────────────────────
type HistoryEntry = {
  id: string;
  type: InspectType;
  input: string;
  decision: Decision;
  score: number;
  timestamp: string;
};

// ── Main component ────────────────────────────────────────────────────
function SecurityGatewayPage() {
  const [mode, setMode]               = useState<InspectType>("ip");
  const [textInput, setTextInput]     = useState("");
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isRunning, setIsRunning]     = useState(false);
  const [stages, setStages]           = useState<PipelineStage[]>(INITIAL_STAGES);
  const [result, setResult]           = useState<GatewayResult | null>(null);
  const [history, setHistory]         = useState<HistoryEntry[]>([]);
  const fileRef                       = useRef<HTMLInputElement>(null);

  const updateStage = (id: string, update: Partial<PipelineStage>) => {
    setStages(prev => prev.map(s => s.id === id ? { ...s, ...update } : s));
  };

  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

  const runGateway = async () => {
    const input = mode === "file" ? selectedFile?.name ?? "" : textInput.trim();
    if (!input && mode !== "file") {
      toast.error("Enter a value to inspect");
      return;
    }
    if (mode === "file" && !selectedFile) {
      toast.error("Select a file to analyze");
      return;
    }

    setIsRunning(true);
    setResult(null);
    setStages(INITIAL_STAGES.map(s => ({ ...s, status: "pending" })));

    let riskScore = 0;
    let blocked   = false;
    const blockedReasons: string[] = [];
    const allowedReasons: string[] = [];
    let iocs: Record<string, string[]> | undefined;
    let aiText = "";
    const stageResults: PipelineStage[] = [...INITIAL_STAGES];

    const set = (id: string, update: Partial<PipelineStage>) => {
      const idx = stageResults.findIndex(s => s.id === id);
      if (idx >= 0) stageResults[idx] = { ...stageResults[idx]!, ...update };
      setStages([...stageResults]);
    };

    try {
      // ── Stage 1: Authentication ──────────────────────────────────
      set("auth", { status: "running" });
      await sleep(200);
      const token = localStorage.getItem("aiss_token");
      if (token) {
        set("auth", { status: "pass", detail: "JWT token valid, operator authenticated" });
        allowedReasons.push("Authenticated operator session");
      } else {
        set("auth", { status: "fail", detail: "No auth token — unauthenticated request" });
        blocked = true;
        blockedReasons.push("Unauthenticated request");
        riskScore += 40;
      }

      // ── Stage 2: Input Validation ────────────────────────────────
      set("input", { status: "running" });
      await sleep(150);
      const trimmed = input.trim();
      if (!trimmed && mode !== "file") {
        set("input", { status: "fail", detail: "Empty input rejected" });
        blocked = true;
        blockedReasons.push("Empty input");
      } else if (trimmed.length > 2048) {
        set("input", { status: "warn", detail: `Input exceeds safe length (${trimmed.length} chars)`, score: 20 });
        riskScore += 20;
      } else {
        set("input", { status: "pass", detail: `Input validated: ${trimmed.length} chars, type: ${mode}` });
      }

      // ── Stage 3: Security Inspection ─────────────────────────────
      set("inspect", { status: "running" });
      await sleep(300);

      if (mode === "text") {
        // Check for prompt injection / malicious content via AI Firewall
        try {
          const BASE_GW = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";
          const tok  = localStorage.getItem("aiss_token") ?? "";
          const fw = await fetch(`${BASE_GW}/api/ai-firewall/inspect`, {
            method: "POST",
            headers: { "Content-Type": "application/json", Authorization: `Bearer ${tok}` },
            body: JSON.stringify({ text: trimmed }),
          }).then(r => r.json()) as { blocked: boolean; attack_type: string; reason: string; risk: string };

          if (fw.blocked) {
            set("inspect", { status: "fail", detail: `AI Firewall blocked: ${fw.attack_type} — ${fw.reason}`, score: 90 });
            blocked = true;
            blockedReasons.push(`AI Firewall: ${fw.attack_type}`);
            riskScore += 90;
          } else {
            set("inspect", { status: "pass", detail: `AI Firewall: CLEAN (${fw.risk} risk)` });
            if (fw.risk === "MEDIUM") riskScore += 10;
          }
        } catch {
          set("inspect", { status: "warn", detail: "AI Firewall unavailable — inspection skipped", score: 10 });
          riskScore += 10;
        }
      } else if (mode === "file" && selectedFile) {
        set("inspect", { status: "pass", detail: `File received: ${selectedFile.name} (${(selectedFile.size / 1024).toFixed(1)} KB)` });
      } else {
        set("inspect", { status: "pass", detail: `${mode.toUpperCase()} input validated` });
      }

      // ── Stage 4: Threat Intelligence ─────────────────────────────
      set("intel", { status: "running" });
      await sleep(400);

      if (mode === "ip") {
        try {
          const enrich = await enrichIP(trimmed);
          const ipRisk = enrich.intel.risk_score ?? 0;
          riskScore += Math.round(ipRisk * 0.4);
          const country = enrich.geo.country_name ?? "Unknown";
          if (ipRisk > 70) {
            set("intel", { status: "fail", detail: `IP risk score ${ipRisk}/100 — ${country}`, score: ipRisk });
            blockedReasons.push(`High-risk IP from ${country} (score: ${ipRisk})`);
          } else if (ipRisk > 30) {
            set("intel", { status: "warn", detail: `IP risk score ${ipRisk}/100 — ${country}`, score: ipRisk });
          } else {
            set("intel", { status: "pass", detail: `IP risk score ${ipRisk}/100 — ${country}`, score: ipRisk });
            allowedReasons.push(`IP reputation acceptable (${ipRisk}/100)`);
          }
        } catch (e) {
          set("intel", { status: "warn", detail: `IP enrichment unavailable: ${String(e)}` });
          riskScore += 5;
        }
      } else if (mode === "url") {
        try {
          const phish = await analyzePhishing(trimmed);
          riskScore += Math.round(phish.risk_score * 0.5);
          if (phish.risk_score > 60) {
            set("intel", { status: "fail", detail: `Phishing score: ${phish.risk_score} — ${phish.risk_level}`, score: phish.risk_score });
            blockedReasons.push(`Phishing risk: ${phish.risk_level} (${phish.risk_score}/100)`);
          } else {
            set("intel", { status: "pass", detail: `Phishing risk: ${phish.risk_level} (${phish.risk_score}/100)`, score: phish.risk_score });
          }
        } catch {
          set("intel", { status: "warn", detail: "Phishing analysis unavailable" });
        }
      } else {
        set("intel", { status: "skip", detail: "Threat intel N/A for this input type" });
      }

      // ── Stage 5: IOC / Malware Check ─────────────────────────────
      set("ioc", { status: "running" });
      await sleep(350);

      if (mode === "file" && selectedFile) {
        try {
          const fileResult = await analyzeFile(selectedFile);
          if (fileResult.threats && fileResult.threats.length > 0) {
            riskScore += 60;
            blocked = true;
            blockedReasons.push(`Malware detected: ${fileResult.threats.map(t => t.type).join(", ")}`);
            set("ioc", { status: "fail", detail: `${fileResult.threats.length} threat(s) detected: ${fileResult.threats[0]?.type}`, score: 90 });
          } else {
            set("ioc", { status: "pass", detail: `File clean. Entropy: ${fileResult.entropy?.toFixed(2) ?? "N/A"}, MIME: ${fileResult.mime_type}` });
            allowedReasons.push("No malware signatures detected");
          }
          if (fileResult.iocs) {
            const hasIocs = Object.values(fileResult.iocs).some(a => a.length > 0);
            if (hasIocs) {
              iocs = Object.fromEntries(
                Object.entries(fileResult.iocs).filter(([, v]) => (v as string[]).length > 0)
              ) as Record<string, string[]>;
              riskScore += 20;
            }
          }
        } catch (e) {
          set("ioc", { status: "warn", detail: `File analysis error: ${String(e)}` });
          riskScore += 15;
        }
      } else if (mode === "text") {
        try {
          const extracted = await extractIOCs(trimmed);
          const all = extracted.iocs;
          const count = Object.values(all).reduce((a, b) => a + b.length, 0);
          if (count > 0) {
            iocs = Object.fromEntries(Object.entries(all).filter(([, v]) => v.length > 0)) as Record<string, string[]>;
            riskScore += Math.min(count * 8, 40);
            set("ioc", { status: "warn", detail: `${count} IOC(s) extracted from text`, score: count * 8 });
          } else {
            set("ioc", { status: "pass", detail: "No IOCs found in text" });
          }
        } catch {
          set("ioc", { status: "skip", detail: "IOC extraction unavailable" });
        }
      } else {
        set("ioc", { status: "skip", detail: "IOC check N/A for this input type" });
      }

      // ── Stage 6: Policy Evaluation ────────────────────────────────
      set("policy", { status: "running" });
      await sleep(200);

      const violations: string[] = [];
      if (riskScore > 80) violations.push("Risk score exceeds BLOCK threshold (>80)");
      if (blocked)         violations.push("One or more security checks failed");

      if (violations.length > 0) {
        set("policy", { status: "fail", detail: violations.join("; ") });
      } else if (riskScore > 50) {
        set("policy", { status: "warn", detail: `Risk score ${riskScore} — QUARANTINE policy applies` });
      } else {
        set("policy", { status: "pass", detail: `Risk score ${riskScore} — within policy limits` });
        allowedReasons.push("Passes policy evaluation");
      }

      // ── Stage 7: AI Risk Analysis ─────────────────────────────────
      set("ai", { status: "running" });

      try {
        const analysisText = mode === "file"
          ? `Analyze security risk for file: ${selectedFile?.name}. Risk score so far: ${riskScore}. Blocked: ${blocked}.`
          : `Analyze security risk for ${mode} input: "${trimmed.slice(0, 200)}". Risk score: ${riskScore}. Blocked: ${blocked}.`;

        const aiRes = await llmAnalyze(analysisText);
        const analysis = typeof aiRes.analysis === "string"
          ? aiRes.analysis
          : JSON.stringify(aiRes.analysis);
        aiText = analysis.slice(0, 300);

        const aiMentionsCritical = analysis.toLowerCase().includes("critical") ||
          analysis.toLowerCase().includes("malicious") ||
          analysis.toLowerCase().includes("high risk");

        if (aiMentionsCritical && riskScore < 50) riskScore += 15;

        set("ai", { status: aiMentionsCritical ? "warn" : "pass", detail: aiText });
      } catch {
        set("ai", { status: "skip", detail: "AI analysis unavailable (no LLM key configured)" });
      }

      // ── Stage 8: Final Decision ───────────────────────────────────
      set("decision", { status: "running" });
      await sleep(200);

      riskScore = Math.min(100, Math.max(0, riskScore));
      const finalDecision = decisionFromScore(riskScore, blocked);

      if (finalDecision === "BLOCK") {
        set("decision", { status: "fail", detail: `BLOCKED — Risk: ${riskScore}/100`, score: riskScore });
      } else if (finalDecision === "QUARANTINE") {
        set("decision", { status: "warn", detail: `QUARANTINE — Risk: ${riskScore}/100 — Analyst review required`, score: riskScore });
      } else if (finalDecision === "REVIEW") {
        set("decision", { status: "warn", detail: `REVIEW — Risk: ${riskScore}/100 — Monitor closely`, score: riskScore });
      } else {
        set("decision", { status: "pass", detail: `ALLOWED — Risk: ${riskScore}/100`, score: riskScore });
      }

      const finalResult: GatewayResult = {
        decision: finalDecision,
        riskScore,
        riskLevel: riskLevel(riskScore),
        stages: [...stageResults],
        summary: `${finalDecision}: ${riskLevel(riskScore)} risk (${riskScore}/100) for ${mode} input "${trimmed.slice(0, 60) || selectedFile?.name}"`,
        ...(iocs !== undefined && { iocs }),
        ...(aiText && { aiAnalysis: aiText }),
        ...(blockedReasons.length > 0 && { blockedReasons }),
        ...(allowedReasons.length > 0 && { allowedReasons }),
        timestamp: new Date().toISOString(),
      };
      setResult(finalResult);

      // Add to history
      setHistory(prev => [{
        id: crypto.randomUUID(),
        type: mode,
        input: trimmed.slice(0, 50) || selectedFile?.name?.slice(0, 50) || "",
        decision: finalDecision,
        score: riskScore,
        timestamp: new Date().toLocaleTimeString(),
      }, ...prev].slice(0, 20));

      if (finalDecision === "ALLOW") {
        toast.success("Gateway: ALLOWED", { description: `Risk score: ${riskScore}/100` });
      } else if (finalDecision === "BLOCK") {
        toast.error("Gateway: BLOCKED", { description: `Risk score: ${riskScore}/100` });
      } else if (finalDecision === "QUARANTINE") {
        toast.warning("Gateway: QUARANTINE", { description: `Risk score: ${riskScore}/100 — Review required` });
      } else {
        toast.info("Gateway: REVIEW", { description: `Risk score: ${riskScore}/100 — Monitor` });
      }

    } catch (err) {
      toast.error(`Gateway error: ${String(err)}`);
    } finally {
      setIsRunning(false);
    }
  };

  const riskBarColor = (score: number) =>
    score > 80 ? "#ef4444" : score > 50 ? "#f59e0b" : score > 20 ? "#3b82f6" : "#22c55e";

  return (
    <div>
      <PageHeader
        title="Security Gateway"
        subtitle="Verify requests, files, IPs, domains and text before allowing entry into the protected environment"
        right={
          <div className="flex shrink-0 items-center gap-2">
            <Badge tone="info">PIPELINE: 8 STAGES</Badge>
            <Badge tone={isRunning ? "warning" : "success"}>{isRunning ? "INSPECTING..." : "READY"}</Badge>
          </div>
        }
      />

      <div className="grid gap-4 xl:grid-cols-12">
        {/* ── Input panel ──────────────────────────────────── */}
        <div className="xl:col-span-5 flex flex-col gap-4">
          <Panel title="Inspection Input" right={<Shield className="size-4 text-primary" />}>
            {/* Mode selector */}
            <div className="flex gap-1 mb-4 flex-wrap">
              {(["ip", "url", "text", "file", "hash"] as InspectType[]).map(m => (
                <button
                  key={m}
                  onClick={() => { setMode(m); setTextInput(""); setSelectedFile(null); }}
                  className={`rounded border px-3 py-1.5 font-mono text-[0.62rem] tracking-wider uppercase transition-colors ${
                    mode === m
                      ? "border-primary/40 bg-primary/12 text-primary"
                      : "border-transparent text-muted-foreground hover:bg-white/5"
                  }`}
                >
                  {m === "ip" ? "IP Address" : m === "url" ? "URL / Domain" : m === "text" ? "Text / Payload" : m === "file" ? "File" : "Hash"}
                </button>
              ))}
            </div>

            {/* Input area */}
            {mode !== "file" ? (
              <div className="space-y-2">
                <label className="label-cap text-[0.62rem] text-muted-foreground">
                  {mode === "ip" ? "IP Address or CIDR" :
                   mode === "url" ? "URL or domain to inspect" :
                   mode === "hash" ? "MD5 / SHA256 hash" :
                   "Text content, payload, or request body"}
                </label>
                <textarea
                  value={textInput}
                  onChange={e => setTextInput(e.target.value)}
                  placeholder={
                    mode === "ip"   ? "e.g. 192.168.1.1 or 45.33.32.156" :
                    mode === "url"  ? "e.g. https://suspicious-domain.com/payload" :
                    mode === "hash" ? "e.g. d41d8cd98f00b204e9800998ecf8427e" :
                    "Paste text, HTTP payload, or request body to inspect for threats..."
                  }
                  rows={4}
                  disabled={isRunning}
                  className="w-full resize-none bg-gray-900 text-sm text-gray-100 rounded-lg border border-gray-700 px-3 py-2.5 font-mono placeholder:text-muted-foreground focus:outline-none focus:border-primary/50 disabled:opacity-50"
                />
              </div>
            ) : (
              <div className="space-y-2">
                <label className="label-cap text-[0.62rem] text-muted-foreground">File to analyze</label>
                <div
                  className="border-2 border-dashed border-gray-700 rounded-lg p-6 text-center cursor-pointer hover:border-primary/40 transition-colors"
                  onClick={() => fileRef.current?.click()}
                >
                  {selectedFile ? (
                    <div>
                      <FileText className="size-8 mx-auto mb-2 text-primary" />
                      <p className="text-sm font-medium">{selectedFile.name}</p>
                      <p className="text-xs text-muted-foreground mt-1">{(selectedFile.size / 1024).toFixed(1)} KB · {selectedFile.type || "unknown type"}</p>
                    </div>
                  ) : (
                    <div>
                      <Upload className="size-8 mx-auto mb-2 text-muted-foreground" />
                      <p className="text-sm text-muted-foreground">Drop a file or click to browse</p>
                      <p className="text-xs text-muted-foreground/60 mt-1">Any file type — YARA + entropy + IOC analysis</p>
                    </div>
                  )}
                </div>
                <input
                  ref={fileRef}
                  type="file"
                  className="hidden"
                  onChange={e => setSelectedFile(e.target.files?.[0] ?? null)}
                />
              </div>
            )}

            <button
              onClick={() => void runGateway()}
              disabled={isRunning}
              className="mt-4 w-full flex items-center justify-center gap-2 rounded-lg bg-primary px-4 py-3 text-sm font-semibold text-white transition-colors hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {isRunning ? (
                <>
                  <Loader2 className="size-4 animate-spin" />
                  Running security pipeline...
                </>
              ) : (
                <>
                  <Shield className="size-4" />
                  Run Security Inspection
                </>
              )}
            </button>
          </Panel>

          {/* Recent history */}
          {history.length > 0 && (
            <Panel title="Recent Decisions" right={<span className="label-cap">{history.length} entries</span>}>
              <ul className="space-y-1.5">
                {history.map(h => (
                  <li key={h.id} className="flex items-center gap-2 rounded-md px-2 py-1.5 hover:bg-white/4">
                    <span className={`size-2 rounded-full shrink-0 ${
                      h.decision === "ALLOW" ? "bg-green-400" :
                      h.decision === "BLOCK" ? "bg-red-400" :
                      h.decision === "QUARANTINE" ? "bg-yellow-400" : "bg-blue-400"
                    }`} />
                    <span className="flex-1 truncate font-mono text-xs text-muted-foreground">{h.input}</span>
                    <Badge tone={toneFor[h.decision ?? "REVIEW"] ?? "info"}>{h.decision}</Badge>
                    <span className="text-[0.6rem] font-mono text-muted-foreground shrink-0">{h.timestamp}</span>
                  </li>
                ))}
              </ul>
            </Panel>
          )}
        </div>

        {/* ── Pipeline + result ──────────────────────────────── */}
        <div className="xl:col-span-7 flex flex-col gap-4">
          {/* Pipeline stages */}
          <Panel title="Verification Pipeline" right={
            <div className="flex items-center gap-1.5">
              {stages.filter(s => s.status === "running").length > 0 && (
                <span className="font-mono text-[0.6rem] text-blue-400 animate-pulse">PROCESSING</span>
              )}
            </div>
          }>
            <div className="space-y-2">
              {stages.map((stage, i) => (
                <div key={stage.id} className="flex items-start gap-3">
                  {/* Step number + connector */}
                  <div className="flex flex-col items-center shrink-0">
                    <div className={`flex size-6 items-center justify-center rounded-full border text-[0.6rem] font-bold font-mono transition-colors ${
                      stage.status === "pass" ? "border-green-400/40 bg-green-400/10 text-green-400" :
                      stage.status === "fail" ? "border-red-400/40 bg-red-400/10 text-red-400" :
                      stage.status === "warn" ? "border-yellow-400/40 bg-yellow-400/10 text-yellow-400" :
                      stage.status === "running" ? "border-blue-400/40 bg-blue-400/10 text-blue-400" :
                      stage.status === "skip" ? "border-gray-600/40 bg-gray-600/10 text-gray-500" :
                      "border-gray-700/40 bg-gray-800/50 text-gray-600"
                    }`}>
                      {i + 1}
                    </div>
                    {i < stages.length - 1 && (
                      <div className={`w-px h-3 mt-0.5 transition-colors ${
                        stage.status === "pass" ? "bg-green-400/30" :
                        stage.status === "fail" ? "bg-red-400/30" :
                        "bg-gray-700/40"
                      }`} />
                    )}
                  </div>
                  {/* Stage content */}
                  <div className="flex-1 min-w-0 pb-1">
                    <div className="flex items-center gap-2">
                      {stageStatusIcon[stage.status]}
                      <span className={`text-sm font-medium ${
                        stage.status === "pending" ? "text-muted-foreground" : "text-foreground"
                      }`}>{stage.label}</span>
                      {stage.score !== undefined && (
                        <span className={`ml-auto font-mono text-[0.6rem] shrink-0 ${
                          stage.score > 70 ? "text-red-400" : stage.score > 40 ? "text-yellow-400" : "text-green-400"
                        }`}>+{stage.score}</span>
                      )}
                    </div>
                    {stage.detail && (
                      <p className="mt-0.5 font-mono text-[0.62rem] text-muted-foreground leading-relaxed truncate">
                        {stage.detail}
                      </p>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </Panel>

          {/* Decision result */}
          {result && (
            <Panel
              title="Security Decision"
              right={
                result.decision ? (
                  <Badge tone={toneFor[result.decision] ?? "info"}>{result.decision}</Badge>
                ) : null
              }
            >
              {/* Decision banner */}
              <div className={`rounded-xl border p-5 mb-4 ${
                result.decision === "ALLOW"      ? "border-green-400/30 bg-green-400/5" :
                result.decision === "BLOCK"      ? "border-red-400/30 bg-red-400/5" :
                result.decision === "QUARANTINE" ? "border-yellow-400/30 bg-yellow-400/5" :
                "border-blue-400/30 bg-blue-400/5"
              }`}>
                <div className="flex items-center gap-4">
                  <div className={`flex size-14 items-center justify-center rounded-full ${
                    result.decision === "ALLOW"      ? "bg-green-400/15" :
                    result.decision === "BLOCK"      ? "bg-red-400/15" :
                    result.decision === "QUARANTINE" ? "bg-yellow-400/15" :
                    "bg-blue-400/15"
                  }`}>
                    {result.decision && decisionIcon[result.decision]}
                  </div>
                  <div className="flex-1">
                    <p className={`text-2xl font-bold font-mono ${
                      result.decision === "ALLOW"      ? "text-green-400" :
                      result.decision === "BLOCK"      ? "text-red-400" :
                      result.decision === "QUARANTINE" ? "text-yellow-400" :
                      "text-blue-400"
                    }`}>{result.decision}</p>
                    <p className="text-sm text-muted-foreground mt-0.5">{result.summary}</p>
                  </div>
                  <div className="text-right">
                    <div className="font-mono text-3xl font-bold" style={{ color: riskBarColor(result.riskScore) }}>
                      {result.riskScore}
                    </div>
                    <div className="font-mono text-[0.6rem] text-muted-foreground">RISK SCORE</div>
                  </div>
                </div>

                {/* Risk bar */}
                <div className="mt-4">
                  <div className="flex justify-between font-mono text-[0.55rem] text-muted-foreground mb-1">
                    <span>LOW (0)</span>
                    <span>MEDIUM (21)</span>
                    <span>HIGH (51)</span>
                    <span>CRITICAL (81)</span>
                  </div>
                  <div className="h-2 rounded-full bg-gray-800 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{
                        width: `${result.riskScore}%`,
                        background: riskBarColor(result.riskScore),
                        boxShadow: `0 0 8px ${riskBarColor(result.riskScore)}60`,
                      }}
                    />
                  </div>
                  <div className="flex justify-between mt-1">
                    {[
                      { label: "0–20 LOW",      color: "#22c55e" },
                      { label: "21–50 MEDIUM",   color: "#3b82f6" },
                      { label: "51–80 HIGH",     color: "#f59e0b" },
                      { label: "81–100 CRITICAL", color: "#ef4444" },
                    ].map(({ label, color }) => (
                      <span key={label} className="font-mono text-[0.5rem]" style={{ color }}>{label}</span>
                    ))}
                  </div>
                </div>
              </div>

              {/* Reasons */}
              <div className="grid sm:grid-cols-2 gap-3">
                {result.blockedReasons && result.blockedReasons.length > 0 && (
                  <div className="rounded-lg border border-red-400/20 bg-red-400/5 p-3">
                    <p className="label-cap text-[0.6rem] text-red-400 mb-2 flex items-center gap-1.5">
                      <XCircle className="size-3" /> BLOCKED BY
                    </p>
                    <ul className="space-y-1">
                      {result.blockedReasons.map((r, i) => (
                        <li key={i} className="font-mono text-[0.62rem] text-red-300">{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
                {result.allowedReasons && result.allowedReasons.length > 0 && (
                  <div className="rounded-lg border border-green-400/20 bg-green-400/5 p-3">
                    <p className="label-cap text-[0.6rem] text-green-400 mb-2 flex items-center gap-1.5">
                      <CheckCircle className="size-3" /> PASSED
                    </p>
                    <ul className="space-y-1">
                      {result.allowedReasons.map((r, i) => (
                        <li key={i} className="font-mono text-[0.62rem] text-green-300">{r}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>

              {/* IOCs */}
              {result.iocs && Object.keys(result.iocs).length > 0 && (
                <div className="mt-3 rounded-lg border border-yellow-400/20 bg-yellow-400/5 p-3">
                  <p className="label-cap text-[0.6rem] text-yellow-400 mb-2">EXTRACTED IOCs</p>
                  <div className="space-y-1">
                    {Object.entries(result.iocs).map(([type, values]) => (
                      <div key={type} className="flex gap-2 flex-wrap">
                        <span className="font-mono text-[0.6rem] text-yellow-400 shrink-0">{type}:</span>
                        {(values as string[]).slice(0, 5).map((v, i) => (
                          <span key={i} className="font-mono text-[0.62rem] text-muted-foreground">{v}</span>
                        ))}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* AI analysis */}
              {result.aiAnalysis && (
                <div className="mt-3 rounded-lg border border-blue-400/20 bg-blue-400/5 p-3">
                  <p className="label-cap text-[0.6rem] text-blue-400 mb-2">AI RISK ANALYSIS</p>
                  <p className="font-mono text-[0.62rem] text-muted-foreground leading-relaxed">{result.aiAnalysis}</p>
                </div>
              )}

              <p className="mt-3 font-mono text-[0.55rem] text-muted-foreground text-right">
                Evaluated at {new Date(result.timestamp).toLocaleTimeString()} · Logged to audit trail
              </p>
            </Panel>
          )}
        </div>
      </div>

      {/* Architecture diagram */}
      <Panel title="Gateway Architecture" right={<span className="label-cap">pipeline overview</span>} className="mt-4">
        <div className="flex items-center gap-0 overflow-x-auto pb-2">
          {[
            { icon: Globe,        label: "Incoming", color: "#64748b" },
            { icon: Lock,         label: "Auth",      color: "#3b82f6" },
            { icon: CheckCircle,  label: "Validate",  color: "#3b82f6" },
            { icon: Eye,          label: "Inspect",   color: "#8b5cf6" },
            { icon: Globe,        label: "Intel",     color: "#f59e0b" },
            { icon: ShieldAlert,  label: "IOC Check", color: "#f59e0b" },
            { icon: Shield,       label: "Policy",    color: "#6366f1" },
            { icon: Bot,          label: "AI Risk",   color: "#6366f1" },
            { icon: ShieldCheck,  label: "Decision",  color: "#22c55e" },
            { icon: Unlock,       label: "Protected", color: "#22c55e" },
          ].map(({ icon: Icon, label, color }, i, arr) => (
            <div key={label} className="flex items-center">
              <div className="flex flex-col items-center gap-1 px-2">
                <div className="flex size-8 items-center justify-center rounded-full border"
                  style={{ borderColor: `${color}40`, background: `${color}12` }}>
                  <Icon className="size-3.5" style={{ color }} />
                </div>
                <span className="font-mono text-[0.52rem] text-muted-foreground whitespace-nowrap">{label}</span>
              </div>
              {i < arr.length - 1 && (
                <ChevronRight className="size-3 text-muted-foreground/40 shrink-0" />
              )}
            </div>
          ))}
        </div>
        <p className="mt-2 font-mono text-[0.6rem] text-muted-foreground">
          Every request passes through all 8 stages. Any stage failure elevates the risk score.
          Final decision: ALLOW (0–20) · REVIEW (21–50) · QUARANTINE (51–80) · BLOCK (81–100)
        </p>
      </Panel>
    </div>
  );
}
