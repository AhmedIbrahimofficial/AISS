"use client";

import { FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import { useRouter } from "next/navigation";

type Decision = "ALLOW" | "HOLD" | "QUARANTINE" | "BLOCK";

interface DashData {
  organizationName?: string;
  stats: {
    threatsTotal: number;
    threats24h: number;
    openIncidents: number;
    pendingApprovals: number;
    quarantine: number;
    learnedRules: number;
    blocked: number;
    quarantined: number;
    held: number;
    allowed: number;
  };
  recentThreats: Array<{
    id: string;
    title: string;
    decision: Decision;
    riskScore: number;
    riskLevel: string;
    createdAt: string;
    summary: string;
  }>;
  openIncidents: Array<{
    id: string;
    title: string;
    stage: string;
    riskLevel: string;
    recommendation: string;
    steps: Array<{ stage: string; status: string; detail?: string }>;
  }>;
  pendingApprovals: Array<{
    id: string;
    incidentId: string;
    action: string;
    reason: string;
    riskLevel: string;
  }>;
  audit: Array<{ id: string; at: string; actor: string; action: string; detail: string }>;
  groqConfigured: boolean;
}

interface GateResult {
  decision: Decision;
  riskScore: number;
  riskLevel: string;
  summary: string;
  stages: Array<{ id: string; label: string; status: string; detail: string }>;
  indicators: string[];
  incidentId?: string;
  aiAnalysis?: string;
  blockedReasons: string[];
}

export default function DashboardPage() {
  const router = useRouter();
  const [data, setData] = useState<DashData | null>(null);
  const [tab, setTab] = useState<"overview" | "gate" | "agent" | "pipeline">("overview");
  const [error, setError] = useState("");
  const [gateType, setGateType] = useState<"file" | "url" | "ip" | "process" | "text">("file");
  const [gateName, setGateName] = useState("invoice.exe.pdf");
  const [gateContent, setGateContent] = useState("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*");
  const [gateUrl, setGateUrl] = useState("https://malware.test/payload");
  const [gateIp, setGateIp] = useState("185.220.101.44");
  const [gateProcess, setGateProcess] = useState("powershell.exe");
  const [gateCmd, setGateCmd] = useState("powershell -enc SQBFAFgAIA...");
  const [gateBusy, setGateBusy] = useState(false);
  const [gateResult, setGateResult] = useState<GateResult | null>(null);
  const [chatInput, setChatInput] = useState("Inspect the latest threats and tell me what to quarantine.");
  const [chatBusy, setChatBusy] = useState(false);
  const [chatLog, setChatLog] = useState<Array<{ role: string; content: string; toolsUsed?: string[] }>>([]);

  const refresh = useCallback(async () => {
    const me = await fetch("/api/auth/me").then((r) => r.json());
    if (!me.setupComplete) {
      router.replace("/setup");
      return;
    }
    if (!me.user) {
      router.replace("/login");
      return;
    }
    const res = await fetch("/api/dashboard");
    if (res.status === 401) {
      router.replace("/login");
      return;
    }
    setData(await res.json());
  }, [router]);

  useEffect(() => {
    refresh().catch(() => setError("Failed to load dashboard"));
    const t = setInterval(() => refresh().catch(() => undefined), 8000);
    return () => clearInterval(t);
  }, [refresh]);

  useEffect(() => {
    fetch("/api/ai/chat")
      .then((r) => r.json())
      .then((d) => {
        if (d.history) {
          setChatLog(
            d.history.map((h: { role: string; content: string; toolsUsed?: string[] }) => ({
              role: h.role,
              content: h.content,
              toolsUsed: h.toolsUsed,
            })),
          );
        }
      })
      .catch(() => undefined);
  }, []);

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    router.replace("/login");
  }

  async function runGate(e: FormEvent) {
    e.preventDefault();
    setGateBusy(true);
    setGateResult(null);
    const payload: Record<string, unknown> = { type: gateType === "ip" ? "network" : gateType, useAi: true };
    if (gateType === "file" || gateType === "text") {
      payload.name = gateName;
      payload.content = gateContent;
      if (gateType === "text") payload.type = "text";
    }
    if (gateType === "url") payload.url = gateUrl;
    if (gateType === "ip") {
      payload.ip = gateIp;
      payload.type = "network";
    }
    if (gateType === "process") {
      payload.processName = gateProcess;
      payload.cmdline = gateCmd;
      payload.type = "process";
    }
    const res = await fetch("/api/gate/inspect", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const json = await res.json();
    setGateBusy(false);
    if (!res.ok) {
      setError(json.error || "Gate failed");
      return;
    }
    setGateResult(json);
    await refresh();
  }

  async function sendChat(e: FormEvent) {
    e.preventDefault();
    if (!chatInput.trim()) return;
    const msg = chatInput.trim();
    setChatInput("");
    setChatBusy(true);
    setChatLog((prev) => [...prev, { role: "user", content: msg }]);
    const res = await fetch("/api/ai/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: msg }),
    });
    const json = await res.json();
    setChatBusy(false);
    if (!res.ok) {
      setChatLog((prev) => [...prev, { role: "assistant", content: json.error || "AI error" }]);
      return;
    }
    setChatLog((prev) => [
      ...prev,
      { role: "assistant", content: json.reply, toolsUsed: json.toolsUsed },
    ]);
    await refresh();
  }

  async function decide(approvalId: string, decision: "approved" | "rejected") {
    await fetch("/api/approvals", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ approvalId, decision }),
    });
    await refresh();
  }

  const stats = data?.stats;
  const tabs = useMemo(
    () =>
      [
        ["overview", "Command Center"],
        ["gate", "Security Gate"],
        ["pipeline", "Response Pipeline"],
        ["agent", "AI Reasoning"],
      ] as const,
    [],
  );

  return (
    <main className="grid-noise min-h-screen px-4 py-6 md:px-8">
      <header className="mx-auto flex max-w-7xl flex-wrap items-center justify-between gap-4 animate-rise">
        <div className="flex items-center gap-3">
          <div className="live-dot" />
          <div>
            <h1 className="text-2xl font-extrabold tracking-tight md:text-3xl">AISS</h1>
            <p className="mono text-xs text-[var(--muted)]">
              {data?.organizationName || "Security Control Plane"} · autonomous
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span
            className={`mono rounded-full px-3 py-1 text-xs ${
              data?.groqConfigured
                ? "bg-[var(--accent-dim)] text-[var(--accent)]"
                : "bg-white/5 text-[var(--warn)]"
            }`}
          >
            Groq {data?.groqConfigured ? "online" : "offline"}
          </span>
          <button
            onClick={logout}
            className="rounded-lg border border-[var(--line)] px-3 py-1.5 text-sm text-[var(--muted)] hover:text-white"
          >
            Sign out
          </button>
        </div>
      </header>

      <nav className="mx-auto mt-8 flex max-w-7xl gap-2 overflow-x-auto">
        {tabs.map(([id, label]) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`rounded-full px-4 py-2 text-sm transition ${
              tab === id
                ? "bg-[var(--accent)] font-semibold text-[#04201c]"
                : "border border-[var(--line)] text-[var(--muted)] hover:text-white"
            }`}
          >
            {label}
          </button>
        ))}
      </nav>

      {error && (
        <p className="mx-auto mt-4 max-w-7xl text-sm text-[var(--danger)]">{error}</p>
      )}

      {!data && (
        <p className="mx-auto mt-10 max-w-7xl text-[var(--muted)]">Loading control plane…</p>
      )}

      {data && tab === "overview" && (
        <section className="mx-auto mt-8 grid max-w-7xl gap-5 lg:grid-cols-12">
          <div className="panel animate-rise col-span-12 p-6 lg:col-span-8">
            <p className="mono text-xs tracking-[0.2em] text-[var(--accent)]">POSTURE</p>
            <h2 className="mt-2 text-3xl font-bold">One dashboard. Real decisions.</h2>
            <p className="mt-2 max-w-2xl text-[var(--muted)]">
              Security Gate scores every artifact before damage. If something slips through, AISS
              runs Detect → Isolate → Analyze → Contain → Remediate → Verify → Learn.
            </p>
            <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-4">
              {[
                ["Threats 24h", stats?.threats24h],
                ["Open incidents", stats?.openIncidents],
                ["Pending approvals", stats?.pendingApprovals],
                ["Quarantine", stats?.quarantine],
              ].map(([label, value]) => (
                <div key={String(label)} className="rounded-2xl border border-[var(--line)] bg-black/20 p-4">
                  <div className="mono text-xs text-[var(--muted)]">{label}</div>
                  <div className="mt-2 text-3xl font-bold">{value ?? 0}</div>
                </div>
              ))}
            </div>
            <div className="mt-5 flex flex-wrap gap-2">
              {[
                ["ALLOW", stats?.allowed],
                ["HOLD", stats?.held],
                ["QUARANTINE", stats?.quarantined],
                ["BLOCK", stats?.blocked],
              ].map(([d, n]) => (
                <span key={String(d)} className={`dec-${d} mono rounded-full px-3 py-1 text-xs`}>
                  {d} {n}
                </span>
              ))}
            </div>
          </div>

          <div className="panel animate-rise col-span-12 p-5 lg:col-span-4" style={{ animationDelay: "80ms" }}>
            <p className="mono text-xs text-[var(--muted)]">LEARNED RULES</p>
            <p className="mt-2 text-4xl font-bold">{stats?.learnedRules ?? 0}</p>
            <p className="mt-2 text-sm text-[var(--muted)]">
              Patterns reinforced after verified incidents feed the next Gate pass.
            </p>
            <button
              onClick={() => setTab("gate")}
              className="mt-6 w-full rounded-xl bg-[var(--accent)] py-3 font-semibold text-[#04201c]"
            >
              Open Security Gate
            </button>
          </div>

          <div className="panel col-span-12 p-5 lg:col-span-7">
            <div className="mb-4 flex items-center justify-between">
              <h3 className="font-semibold">Recent gate decisions</h3>
              <button onClick={() => refresh()} className="mono text-xs text-[var(--accent)]">
                refresh
              </button>
            </div>
            <div className="space-y-2">
              {data.recentThreats.length === 0 && (
                <p className="text-sm text-[var(--muted)]">No inspections yet — run the Security Gate.</p>
              )}
              {data.recentThreats.map((t) => (
                <div
                  key={t.id}
                  className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--line)] bg-black/15 px-3 py-2"
                >
                  <div>
                    <div className="font-medium">{t.title}</div>
                    <div className="mono text-xs text-[var(--muted)]">{t.summary}</div>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`risk-${t.riskLevel} mono text-xs`}>{t.riskScore}</span>
                    <span className={`dec-${t.decision} mono rounded-full px-2 py-0.5 text-xs`}>
                      {t.decision}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="panel col-span-12 p-5 lg:col-span-5">
            <h3 className="font-semibold">Audit stream</h3>
            <div className="mt-3 max-h-80 space-y-2 overflow-auto">
              {data.audit.map((a) => (
                <div key={a.id} className="border-b border-[var(--line)] pb-2 text-sm">
                  <div className="mono text-[10px] text-[var(--muted)]">{a.at}</div>
                  <div>
                    <span className="text-[var(--accent)]">{a.action}</span> · {a.detail}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {data && tab === "gate" && (
        <section className="mx-auto mt-8 grid max-w-7xl gap-5 lg:grid-cols-2">
          <form onSubmit={runGate} className="panel animate-rise space-y-4 p-6">
            <p className="mono text-xs tracking-[0.2em] text-[var(--accent)]">SECURITY GATE</p>
            <h2 className="text-2xl font-bold">Inspect before damage</h2>
            <p className="text-sm text-[var(--muted)]">
              Detect → risk-score → ALLOW / HOLD / QUARANTINE / BLOCK. Suspicious files, processes,
              and network activity are stopped at the gate.
            </p>
            <div className="flex flex-wrap gap-2">
              {(["file", "url", "ip", "process", "text"] as const).map((t) => (
                <button
                  key={t}
                  type="button"
                  onClick={() => setGateType(t)}
                  className={`rounded-full px-3 py-1 text-xs uppercase ${
                    gateType === t ? "bg-[var(--accent)] text-[#04201c]" : "border border-[var(--line)]"
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
            {(gateType === "file" || gateType === "text") && (
              <>
                <input
                  className="w-full rounded-xl border border-[var(--line)] bg-black/20 px-3 py-2"
                  value={gateName}
                  onChange={(e) => setGateName(e.target.value)}
                  placeholder="filename"
                />
                <textarea
                  className="min-h-28 w-full rounded-xl border border-[var(--line)] bg-black/20 px-3 py-2 mono text-sm"
                  value={gateContent}
                  onChange={(e) => setGateContent(e.target.value)}
                  placeholder="file content / sample"
                />
              </>
            )}
            {gateType === "url" && (
              <input
                className="w-full rounded-xl border border-[var(--line)] bg-black/20 px-3 py-2"
                value={gateUrl}
                onChange={(e) => setGateUrl(e.target.value)}
              />
            )}
            {gateType === "ip" && (
              <input
                className="w-full rounded-xl border border-[var(--line)] bg-black/20 px-3 py-2"
                value={gateIp}
                onChange={(e) => setGateIp(e.target.value)}
              />
            )}
            {gateType === "process" && (
              <>
                <input
                  className="w-full rounded-xl border border-[var(--line)] bg-black/20 px-3 py-2"
                  value={gateProcess}
                  onChange={(e) => setGateProcess(e.target.value)}
                />
                <input
                  className="w-full rounded-xl border border-[var(--line)] bg-black/20 px-3 py-2 mono text-sm"
                  value={gateCmd}
                  onChange={(e) => setGateCmd(e.target.value)}
                />
              </>
            )}
            <button
              type="submit"
              disabled={gateBusy}
              className="w-full rounded-xl bg-[var(--accent)] py-3 font-semibold text-[#04201c] disabled:opacity-60"
            >
              {gateBusy ? "Inspecting…" : "Run Security Gate"}
            </button>
          </form>

          <div className="panel p-6">
            {!gateResult && (
              <p className="text-[var(--muted)]">Results appear here with stage-by-stage scoring.</p>
            )}
            {gateResult && (
              <div className="animate-rise space-y-4">
                <div className="flex flex-wrap items-center gap-3">
                  <span className={`dec-${gateResult.decision} rounded-full px-3 py-1 mono text-sm`}>
                    {gateResult.decision}
                  </span>
                  <span className={`risk-${gateResult.riskLevel} text-2xl font-bold`}>
                    {gateResult.riskScore}
                  </span>
                  <span className="text-[var(--muted)]">{gateResult.riskLevel}</span>
                </div>
                <p>{gateResult.summary}</p>
                {gateResult.aiAnalysis && (
                  <div className="rounded-xl border border-[var(--line)] bg-black/20 p-3 text-sm">
                    <div className="mono text-xs text-[var(--accent)]">AI ANALYSIS</div>
                    <p className="mt-1">{gateResult.aiAnalysis}</p>
                  </div>
                )}
                <div className="space-y-2">
                  {gateResult.stages.map((s) => (
                    <div key={s.id} className="flex justify-between gap-3 border-b border-[var(--line)] py-2 text-sm">
                      <div>
                        <div className="font-medium">{s.label}</div>
                        <div className="text-[var(--muted)]">{s.detail}</div>
                      </div>
                      <span className="mono text-xs uppercase text-[var(--muted)]">{s.status}</span>
                    </div>
                  ))}
                </div>
                {gateResult.incidentId && (
                  <p className="mono text-xs text-[var(--warn)]">
                    Incident opened: {gateResult.incidentId}
                  </p>
                )}
              </div>
            )}
          </div>
        </section>
      )}

      {data && tab === "pipeline" && (
        <section className="mx-auto mt-8 grid max-w-7xl gap-5 lg:grid-cols-2">
          <div className="panel p-6">
            <h2 className="text-2xl font-bold">Response pipeline</h2>
            <p className="mt-2 text-sm text-[var(--muted)]">
              Detect → Isolate → Analyze → Contain → Remediate → Verify → Learn. High-impact
              actions wait for approval.
            </p>
            <div className="mt-5 space-y-3">
              {data.openIncidents.length === 0 && (
                <p className="text-sm text-[var(--muted)]">No open incidents.</p>
              )}
              {data.openIncidents.map((inc) => (
                <div key={inc.id} className="rounded-xl border border-[var(--line)] bg-black/15 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="font-semibold">{inc.title}</div>
                    <span className={`risk-${inc.riskLevel} mono text-xs`}>{inc.riskLevel}</span>
                  </div>
                  <div className="mono mt-1 text-xs text-[var(--accent)]">STAGE {inc.stage}</div>
                  <p className="mt-2 text-sm text-[var(--muted)]">{inc.recommendation}</p>
                  <div className="mt-3 flex flex-wrap gap-1">
                    {inc.steps.map((s) => (
                      <span
                        key={s.stage}
                        className={`mono rounded-full px-2 py-0.5 text-[10px] ${
                          s.status === "done"
                            ? "bg-[var(--accent-dim)] text-[var(--accent)]"
                            : s.status === "awaiting_approval"
                              ? "bg-white/10 text-[var(--warn)]"
                              : "bg-black/20 text-[var(--muted)]"
                        }`}
                      >
                        {s.stage}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="panel p-6">
            <h2 className="text-2xl font-bold">Approval gates</h2>
            <div className="mt-5 space-y-3">
              {data.pendingApprovals.length === 0 && (
                <p className="text-sm text-[var(--muted)]">No pending approvals.</p>
              )}
              {data.pendingApprovals.map((a) => (
                <div key={a.id} className="rounded-xl border border-[var(--line)] bg-black/15 p-4">
                  <div className="mono text-xs text-[var(--warn)]">{a.riskLevel}</div>
                  <div className="mt-1 font-medium">{a.action}</div>
                  <p className="mt-1 text-sm text-[var(--muted)]">{a.reason}</p>
                  <div className="mt-3 flex gap-2">
                    <button
                      onClick={() => decide(a.id, "approved")}
                      className="rounded-lg bg-[var(--accent)] px-3 py-1.5 text-sm font-semibold text-[#04201c]"
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => decide(a.id, "rejected")}
                      className="rounded-lg border border-[var(--line)] px-3 py-1.5 text-sm"
                    >
                      Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {data && tab === "agent" && (
        <section className="mx-auto mt-8 grid max-w-7xl gap-5">
          <div className="panel flex min-h-[70vh] flex-col p-6">
            <div className="mb-4">
              <p className="mono text-xs tracking-[0.2em] text-[var(--accent)]">GROQ · TOOL USE</p>
              <h2 className="text-2xl font-bold">Security Reasoning Layer</h2>
              <p className="mt-1 text-sm text-[var(--muted)]">
                Talk to AISS. It can inspect artifacts, list threats, manage quarantine, and resolve
                approvals via real tools — not chat theater.
              </p>
            </div>
            <div className="flex-1 space-y-3 overflow-auto rounded-xl border border-[var(--line)] bg-black/20 p-4">
              {chatLog.length === 0 && (
                <p className="text-sm text-[var(--muted)]">
                  Try: “Scan EICAR test content and quarantine if needed.”
                </p>
              )}
              {chatLog.map((m, i) => (
                <div
                  key={i}
                  className={`rounded-xl px-3 py-2 text-sm ${
                    m.role === "user" ? "bg-[var(--accent-dim)]" : "bg-white/5"
                  }`}
                >
                  <div className="mono text-[10px] uppercase text-[var(--muted)]">{m.role}</div>
                  <div className="mt-1 whitespace-pre-wrap">{m.content}</div>
                  {m.toolsUsed && m.toolsUsed.length > 0 && (
                    <div className="mono mt-2 text-[10px] text-[var(--accent)]">
                      tools: {m.toolsUsed.join(", ")}
                    </div>
                  )}
                </div>
              ))}
              {chatBusy && <p className="mono text-xs text-[var(--muted)]">reasoning…</p>}
            </div>
            <form onSubmit={sendChat} className="mt-4 flex gap-2">
              <input
                className="flex-1 rounded-xl border border-[var(--line)] bg-black/20 px-4 py-3 outline-none focus:border-[var(--accent)]"
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                placeholder="Ask AISS to investigate…"
              />
              <button
                type="submit"
                disabled={chatBusy}
                className="rounded-xl bg-[var(--accent)] px-5 font-semibold text-[#04201c] disabled:opacity-60"
              >
                Send
              </button>
            </form>
          </div>
        </section>
      )}
    </main>
  );
}
