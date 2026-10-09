import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import QRCode from "qrcode";
import { PageHeader } from "@/components/soc/AppShell";
import { ModuleHealth } from "@/components/soc/ModuleHealth";
import { SetupWizard } from "@/components/soc/SetupWizard";
import { useWizard, useLibraries, useLLMProviders, useBackendStatus } from "@/hooks/useAISS";
import {
  generatePairingToken, listDevices, revokeDevice, type DeviceInfo,
  getSystemConfig, updateSystemConfig,
} from "@/lib/api";
import {
  Monitor, Smartphone, Server, Wifi, RefreshCw,
  Plus, Trash2, Copy, QrCode, Clock, CheckCircle2,
  Shield, Laptop, Save, Settings, Network, Brain,
  AlertTriangle, Activity, Wrench,
} from "lucide-react";

export const Route = createFileRoute("/system")({
  head: () => ({
    meta: [{ title: "System — AISS" }],
  }),
  component: SystemPage,
});

// ── Reusable toggle ───────────────────────────────────────────────────────────
function Toggle({ label, hint, initial }: { label: string; hint: string; initial: boolean }) {
  const [on, setOn] = useState(initial);
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-b border-[var(--hairline)] py-3 last:border-0">
      <div>
        <p className="text-sm">{label}</p>
        <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p>
      </div>
      <button
        onClick={() => { setOn((v) => !v); toast.success(`${label} ${!on ? "enabled" : "disabled"}`); }}
        aria-pressed={on}
        className={`h-6 w-11 shrink-0 rounded-full border transition-colors ${
          on ? "border-primary/50 bg-primary/30" : "border-[var(--hairline)] bg-white/6"
        }`}
      >
        <span
          className={`block size-4 rounded-full bg-foreground transition-transform ${
            on ? "translate-x-6" : "translate-x-1"
          }`}
        />
      </button>
    </div>
  );
}

// ── Panel wrapper ─────────────────────────────────────────────────────────────
function Panel({
  title,
  icon: Icon,
  children,
  right,
}: {
  title: string;
  icon?: React.ComponentType<{ className?: string }>;
  children: React.ReactNode;
  right?: React.ReactNode;
}) {
  return (
    <div className="panel overflow-hidden">
      <div className="flex items-center justify-between border-b border-[var(--hairline)] px-4 py-3">
        <div className="flex items-center gap-2">
          {Icon && <Icon className="size-4 text-primary" />}
          <p className="text-sm font-semibold">{title}</p>
        </div>
        {right}
      </div>
      <div className="p-4">{children}</div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Device Pairing Panel
// ─────────────────────────────────────────────────────────────────────────────
function DevicePairingPanel() {
  const qc = useQueryClient();
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [pairingToken, setPairingToken] = useState<string | null>(null);
  const [countdown, setCountdown] = useState(0);
  const [newName, setNewName] = useState("My Device");
  const [newType, setNewType] = useState("desktop");
  const [showQR, setShowQR] = useState(false);
  const [copied, setCopied] = useState(false);

  const { data: devData, isLoading } = useQuery({
    queryKey: ["devices"],
    queryFn: listDevices,
    refetchInterval: 10_000,
  });

  const genToken = useMutation({
    mutationFn: () => generatePairingToken(newName, newType),
    onSuccess: (data) => {
      setPairingToken(data.pairing_token);
      setCountdown(data.expires_in_seconds);
      setShowQR(false);
      void qc.invalidateQueries({ queryKey: ["devices"] });
      toast.success("Pairing token generated — valid for 15 minutes");
    },
    onError: (e) => toast.error(`Failed: ${String(e)}`),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => revokeDevice(id),
    onSuccess: () => { void qc.invalidateQueries({ queryKey: ["devices"] }); toast.success("Device revoked"); },
    onError: (e) => toast.error(`Failed: ${String(e)}`),
  });

  useEffect(() => {
    if (!pairingToken || countdown <= 0) return;
    const t = setInterval(() => {
      setCountdown((c) => {
        if (c <= 1) { setPairingToken(null); clearInterval(t); return 0; }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [pairingToken, countdown]);

  useEffect(() => {
    if (!pairingToken || !showQR || !canvasRef.current) return;
    const BASE = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";
    QRCode.toCanvas(canvasRef.current, `${BASE}/api/auth/devices/pair?token=${pairingToken}`, {
      width: 200, margin: 2,
      color: { dark: "#10b981", light: "#070d0b" },
    }).catch(() => {});
  }, [pairingToken, showQR]);

  const fmtCountdown = (s: number) =>
    `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  const devices = devData?.devices ?? [];

  return (
    <div className="flex flex-col gap-4">
      <Panel title="Connect a New Device" icon={Network} right={
        <span className="rounded-md border border-[var(--hairline)] px-2 py-0.5 font-mono text-[0.6rem] text-muted-foreground">
          {devices.filter((d) => d.is_paired && !d.is_revoked).length} paired
        </span>
      }>
        <div className="flex flex-col gap-4">
          <div className="flex gap-2">
            <div className="flex-1">
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Device Name</label>
              <input
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 px-3 py-2 text-sm outline-none focus:border-primary/50"
              />
            </div>
            <div>
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Type</label>
              <select
                value={newType}
                onChange={(e) => setNewType(e.target.value)}
                className="rounded-lg border border-[var(--hairline)] bg-[#0d1a15] px-3 py-2 text-sm outline-none"
              >
                <option value="desktop">Desktop</option>
                <option value="laptop">Laptop</option>
                <option value="server">Server</option>
                <option value="mobile">Mobile</option>
              </select>
            </div>
          </div>

          <button
            onClick={() => genToken.mutate()}
            disabled={genToken.isPending}
            className="flex items-center justify-center gap-2 rounded-lg border border-primary/40 bg-primary/12 px-4 py-2.5 text-sm font-semibold text-primary transition hover:bg-primary/20 disabled:opacity-50"
          >
            <Plus className="size-4" />
            {genToken.isPending ? "Generating…" : "Generate Pairing Token"}
          </button>

          {pairingToken && (
            <div className="rounded-xl border border-primary/20 bg-primary/5 p-4">
              <div className="mb-3 flex items-center justify-between">
                <p className="text-sm font-semibold text-primary">Pairing Token</p>
                <div className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                  <Clock className="size-3" />
                  <span className={countdown < 60 ? "text-[var(--critical)]" : ""}>{fmtCountdown(countdown)}</span>
                </div>
              </div>
              <div className="mb-3 flex items-center gap-2 rounded-lg border border-[var(--hairline)] bg-black/30 px-3 py-2.5">
                <code className="flex-1 break-all font-mono text-xs">{pairingToken}</code>
                <button onClick={() => { void navigator.clipboard.writeText(pairingToken); setCopied(true); setTimeout(() => setCopied(false), 2000); toast.success("Copied"); }}
                  className="shrink-0 rounded p-1 text-muted-foreground hover:text-primary">
                  {copied ? <CheckCircle2 className="size-4 text-[var(--success)]" /> : <Copy className="size-4" />}
                </button>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={() => setShowQR((v) => !v)}
                  className="flex items-center gap-1.5 rounded-lg border border-[var(--hairline)] px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground">
                  <QrCode className="size-3.5" /> {showQR ? "Hide QR" : "Show QR Code"}
                </button>
              </div>
              {showQR && <div className="mt-3 flex justify-center"><canvas ref={canvasRef} className="rounded-xl" /></div>}
            </div>
          )}
        </div>
      </Panel>

      <Panel title="Registered Devices" icon={Monitor} right={
        <button onClick={() => qc.invalidateQueries({ queryKey: ["devices"] })}
          className="p-1 text-muted-foreground hover:text-foreground">
          <RefreshCw className="size-3.5" />
        </button>
      }>
        {isLoading ? (
          <div className="flex h-20 items-center justify-center">
            <div className="size-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          </div>
        ) : devices.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-6 text-center">
            <Wifi className="size-8 text-muted-foreground opacity-20" />
            <p className="text-sm text-muted-foreground">No devices paired yet</p>
          </div>
        ) : (
          <ul className="divide-y divide-[var(--hairline)]">
            {devices.map((d) => (
              <li key={d.id} className="flex items-center gap-3 py-3 first:pt-0 last:pb-0">
                <div className="flex size-8 items-center justify-center rounded-lg border border-[var(--hairline)] bg-white/3">
                  {d.device_type === "mobile" ? <Smartphone className="size-4 text-muted-foreground" />
                    : d.device_type === "server" ? <Server className="size-4 text-muted-foreground" />
                    : d.device_type === "laptop" ? <Laptop className="size-4 text-muted-foreground" />
                    : <Monitor className="size-4 text-muted-foreground" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="truncate text-sm font-medium">{d.device_name}</p>
                    <span
                      className="rounded-md border px-1.5 py-0.5 font-mono text-[0.55rem] font-semibold"
                      style={
                        d.status === "connected" || d.status === "paired"
                          ? { color: "var(--success)", borderColor: "var(--success)33" }
                          : d.status === "revoked"
                          ? { color: "var(--critical)", borderColor: "var(--critical)33" }
                          : { color: "var(--warning)", borderColor: "var(--warning)33" }
                      }
                    >
                      {d.status.toUpperCase()}
                    </span>
                  </div>
                  <p className="mt-0.5 truncate font-mono text-[0.6rem] text-muted-foreground">
                    {d.hostname ?? d.platform ?? d.device_type}
                    {d.last_seen_ip ? ` · ${d.last_seen_ip}` : ""}
                  </p>
                </div>
                {!d.is_revoked && (
                  <button
                    onClick={() => { if (confirm(`Revoke "${d.device_name}"?`)) revoke.mutate(d.id); }}
                    className="shrink-0 rounded p-1.5 text-muted-foreground hover:text-[var(--critical)]">
                    <Trash2 className="size-4" />
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Threat Intel Keys Tab (company-managed — read only for users)
// ─────────────────────────────────────────────────────────────────────────────
function ThreatIntelTab() {
  const { data, isLoading } = useQuery({
    queryKey: ["systemConfig"],
    queryFn: getSystemConfig,
    staleTime: 30_000,
  });
  const qc = useQueryClient();
  const [edits, setEdits] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  // Only show non-AI, non-OPENROUTER keys (threat intel only)
  const threatIntelKeys = [
    "VIRUSTOTAL_API_KEY",
    "SHODAN_API_KEY",
    "CENSYS_API_ID",
    "CENSYS_API_SECRET",
    "MAXMIND_LICENSE_KEY",
  ];

  const handleSave = async () => {
    if (Object.keys(edits).length === 0) return;
    setSaving(true);
    try {
      const result = await updateSystemConfig(edits);
      toast.success(result.message);
      setEdits({});
      void qc.invalidateQueries({ queryKey: ["systemConfig"] });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save");
    } finally {
      setSaving(false);
    }
  };

  if (isLoading) return <div className="flex items-center gap-2 text-muted-foreground py-4"><RefreshCw className="size-4 animate-spin" /> Loading…</div>;
  if (!data) return <p className="text-sm text-muted-foreground">Unable to load configuration.</p>;

  return (
    <div className="flex flex-col gap-4">
      {/* AI Key notice */}
      <div className="rounded-xl border border-primary/20 bg-primary/5 p-4">
        <div className="flex items-start gap-3">
          <Brain className="size-5 shrink-0 text-primary mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-primary">AI is company-managed</p>
            <p className="mt-1 text-[0.78rem] text-muted-foreground leading-relaxed">
              AISS uses a company-wide OpenRouter API key for all AI features (Claude, GPT-4, Gemini, Llama).
              You do not need your own AI API key — AI is available to all users automatically.
            </p>
          </div>
        </div>
      </div>

      <Panel title="Threat Intelligence API Keys" icon={Shield}>
        <div className="space-y-3">
          {threatIntelKeys.map((key) => {
            const cfg = data.config[key];
            return (
              <div key={key} className="grid grid-cols-[180px_1fr] items-center gap-3">
                <label className="font-mono text-xs text-muted-foreground">{key}</label>
                <input
                  type="password"
                  defaultValue={cfg?.value ?? ""}
                  placeholder={cfg?.masked ? "(configured)" : "Enter key…"}
                  onChange={(e) => {
                    if (e.target.value) setEdits((p) => ({ ...p, [key]: e.target.value }));
                    else { const { [key]: _, ...rest } = edits; setEdits(rest); }
                  }}
                  className="rounded-lg border border-[var(--hairline)] bg-white/4 px-3 py-1.5 text-sm outline-none focus:border-primary/50"
                />
              </div>
            );
          })}
        </div>
        <div className="mt-4 flex items-center gap-3">
          <button
            onClick={() => void handleSave()}
            disabled={saving || Object.keys(edits).length === 0}
            className="flex items-center gap-2 rounded-lg border border-primary/40 bg-primary/15 px-4 py-2 text-sm font-semibold text-primary transition hover:bg-primary/25 disabled:opacity-40"
          >
            {saving ? <RefreshCw className="size-4 animate-spin" /> : <Save className="size-4" />}
            {saving ? "Saving…" : `Save (${Object.keys(edits).length} changes)`}
          </button>
        </div>
      </Panel>

      <div className="rounded-lg border border-[var(--hairline)] bg-white/2 px-4 py-3">
        <p className="text-[0.7rem] font-semibold text-muted-foreground mb-2">What these keys enable</p>
        <ul className="space-y-1">
          {[
            ["VirusTotal", "Hash and URL reputation lookups during threat analysis"],
            ["Shodan", "Internet-exposed service fingerprinting for attacker IPs"],
            ["Censys", "Additional host intelligence for IP enrichment"],
            ["MaxMind", "Accurate GeoIP location for threat source mapping"],
          ].map(([k, v]) => (
            <li key={k} className="flex items-start gap-2">
              <CheckCircle2 className="mt-0.5 size-3 shrink-0 text-primary" />
              <span className="text-[0.65rem] text-muted-foreground">
                <strong className="text-foreground">{k}:</strong> {v}
              </span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main System Page
// ─────────────────────────────────────────────────────────────────────────────
function SystemPage() {
  const [tab, setTab] = useState<"detection" | "response" | "devices" | "intel">("detection");
  const [showWizard, setShowWizard] = useState(false);
  const { data: wizard } = useWizard();
  const { data: libData } = useLibraries();
  const { data: llmData } = useLLMProviders();
  const { online } = useBackendStatus();

  const completed = wizard?.completed ?? 0;
  const total = wizard?.total_questions ?? 0;
  const pct = total > 0 ? Math.round((completed / total) * 100) : 0;

  const TABS = [
    { id: "detection" as const, label: "Detection", icon: Activity },
    { id: "response"  as const, label: "Response Policy", icon: Shield },
    { id: "devices"   as const, label: "Device Pairing", icon: Network },
    { id: "intel"     as const, label: "Threat Intel", icon: Brain },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="System"
        subtitle="Detection modules, response policies, device pairing, and integrations"
        right={
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-2 rounded-lg border border-primary/40 bg-primary/12 px-4 py-2 text-sm font-semibold text-primary transition hover:bg-primary/20"
          >
            <Wrench className="size-4" /> Config Wizard
          </button>
        }
      />

      {showWizard && <SetupWizard onClose={() => setShowWizard(false)} />}

      {/* Config progress bar */}
      <div className="panel px-4 py-3">
        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium">AISS Configuration</p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              {completed}/{total} settings configured ·{" "}
              {llmData?.total_providers
                ? `AI active via OpenRouter (${llmData.total_providers} model${llmData.total_providers !== 1 ? "s" : ""})`
                : "AI not yet configured — contact your administrator"}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <div className="h-1.5 w-32 overflow-hidden rounded-full bg-white/8">
              <div className="h-full rounded-full bg-primary" style={{ width: `${pct}%` }} />
            </div>
            <span className="font-mono text-xs text-muted-foreground">{pct}%</span>
            <span
              className="rounded-md border px-2 py-0.5 font-mono text-[0.6rem] font-semibold"
              style={online
                ? { color: "var(--success)", borderColor: "var(--success)33" }
                : { color: "var(--critical)", borderColor: "var(--critical)33" }}
            >
              {online ? "ONLINE" : "OFFLINE"}
            </span>
          </div>
        </div>
      </div>

      {/* Tab bar */}
      <div className="flex flex-wrap gap-1 rounded-xl border border-[var(--hairline)] bg-black/20 p-1 w-fit">
        {TABS.map((t) => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-all ${
              tab === t.id
                ? "bg-primary/15 text-primary border border-primary/30"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <t.icon className="size-4" />
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Detection Tab ─────────────────────────────────────────── */}
      {tab === "detection" && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Panel title="Detection Tuning" icon={Activity}>
            <Toggle label="Behavioural analytics"     hint="UEBA baseline over 30 days"                    initial />
            <Toggle label="Threat intel enrichment"   hint="STIX/TAXII feeds, refreshed every 6h"          initial />
            <Toggle label="Low-confidence alerts"     hint="Surface detections below 70% model confidence" initial={false} />
            <Toggle label="Online ML anomaly scoring" hint="River HalfSpaceTrees — adapts to live traffic"  initial />
            <Toggle label="YARA memory scanning"      hint="Scan process memory for shellcode patterns"    initial />
            <Toggle label="Ransomware detection"      hint="Behavioral pattern monitoring + entropy analysis" initial />
          </Panel>

          <Panel title="Library Status" icon={Settings}>
            {libData ? (
              <div className="space-y-3">
                <div className="flex gap-2">
                  <span className="rounded-md border border-[var(--success)]/30 bg-[var(--success)]/10 px-2 py-0.5 font-mono text-[0.6rem] text-[var(--success)]">
                    {libData.enabled} enabled
                  </span>
                  {libData.disabled > 0 && (
                    <span className="rounded-md border border-[var(--warning)]/30 bg-[var(--warning)]/10 px-2 py-0.5 font-mono text-[0.6rem] text-[var(--warning)]">
                      {libData.disabled} disabled
                    </span>
                  )}
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
                  <div
                    className="h-full rounded-full bg-primary"
                    style={{ width: `${Math.round((libData.enabled / Math.max(libData.total, 1)) * 100)}%` }}
                  />
                </div>
                <div className="max-h-48 overflow-y-auto space-y-1">
                  {libData.libraries.map((lib) => (
                    <div key={lib.name} className="flex items-center justify-between py-1">
                      <span className="text-xs text-muted-foreground">{lib.name}</span>
                      <div className="flex items-center gap-2">
                        {lib.version && <span className="font-mono text-[0.6rem] text-muted-foreground">{lib.version}</span>}
                        <span
                          className="size-2 rounded-full"
                          style={{ background: lib.enabled ? "var(--success)" : "var(--critical)" }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">Connect to backend to view.</p>
            )}
          </Panel>

          <div className="xl:col-span-2">
            <ModuleHealth />
          </div>
        </div>
      )}

      {/* ── Response Policy Tab ───────────────────────────────────── */}
      {tab === "response" && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Panel title="Automated Response Policy" icon={Shield}>
            <Toggle label="Auto-quarantine malicious files"  hint="Moves file to encrypted quarantine immediately" initial />
            <Toggle label="Auto-block attacker IPs"          hint="Adds Windows Firewall rules with 24h expiry"    initial />
            <Toggle label="Auto-kill cryptominers"           hint="Terminates process immediately on detection"     initial />
            <Toggle label="Suspend before forensics"         hint="Pause process to collect evidence first"        initial />
            <Toggle label="Emergency ransomware response"    hint="Kill shadow copy deletion, terminate processes"  initial />
          </Panel>

          <Panel title="Approval Requirements" icon={AlertTriangle}>
            <p className="text-[0.72rem] text-muted-foreground mb-4 leading-relaxed">
              HIGH and CRITICAL risk operations require explicit user approval before executing.
              AISS will present exactly what will happen and wait for your confirmation.
            </p>
            <div className="space-y-2">
              {[
                { action: "Process kill", risk: "HIGH" },
                { action: "File quarantine", risk: "HIGH" },
                { action: "IP block", risk: "MEDIUM" },
                { action: "Process tree termination", risk: "CRITICAL" },
                { action: "Emergency ransomware response", risk: "CRITICAL" },
              ].map((item) => (
                <div key={item.action} className="flex items-center justify-between py-2 border-b border-[var(--hairline)] last:border-0">
                  <span className="text-sm">{item.action}</span>
                  <span
                    className="rounded-md border px-2 py-0.5 font-mono text-[0.58rem] font-semibold"
                    style={
                      item.risk === "CRITICAL"
                        ? { color: "var(--critical)", borderColor: "var(--critical)33" }
                        : item.risk === "HIGH"
                        ? { color: "#f97316", borderColor: "#f9731633" }
                        : { color: "var(--warning)", borderColor: "var(--warning)33" }
                    }
                  >
                    {item.risk} — Requires Approval
                  </span>
                </div>
              ))}
            </div>
          </Panel>
        </div>
      )}

      {/* ── Devices Tab ───────────────────────────────────────────── */}
      {tab === "devices" && <DevicePairingPanel />}

      {/* ── Threat Intel Tab ──────────────────────────────────────── */}
      {tab === "intel" && <ThreatIntelTab />}
    </div>
  );
}
