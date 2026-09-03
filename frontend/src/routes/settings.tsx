import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect, useRef } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import QRCode from "qrcode";
import { PageHeader } from "@/components/soc/AppShell";
import { Panel } from "@/components/soc/Panel";
import { Badge } from "@/components/soc/ui";
import { ActionButton } from "@/components/soc/actions";
import { ModuleHealth } from "@/components/soc/ModuleHealth";
import { SetupWizard } from "@/components/soc/SetupWizard";
import { useWizard, useLibraries, useLLMProviders, useBackendStatus } from "@/hooks/useAISS";
import {
  generatePairingToken, listDevices, revokeDevice, type DeviceInfo,
  getSystemConfig, updateSystemConfig,
} from "@/lib/api";
import {
  Monitor, Smartphone, Server, Wifi, WifiOff, RefreshCw,
  Plus, Trash2, Copy, QrCode, Clock, CheckCircle2, XCircle,
  Shield, Laptop, Key, Save,
} from "lucide-react";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings & Devices — AISS Security Console" },
    ],
  }),
  component: SettingsPage,
});

// ── Toggle component ──────────────────────────────────────────────────
function Toggle({ label, hint, initial }: { label: string; hint: string; initial: boolean }) {
  const [on, setOn] = useState(initial);
  return (
    <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 border-b border-[var(--hairline)] py-3 last:border-0">
      <div>
        <p className="text-sm">{label}</p>
        <p className="mt-0.5 text-xs text-muted-foreground">{hint}</p>
      </div>
      <button
        onClick={() => { setOn(v => !v); toast.success(`${label} ${!on ? "enabled" : "disabled"}`); }}
        aria-pressed={on}
        className={`h-6 w-11 shrink-0 rounded-full border transition-colors ${on ? "border-primary/50 bg-primary/30" : "border-[var(--hairline)] bg-white/6"}`}
      >
        <span className={`block size-4 rounded-full bg-foreground transition-transform ${on ? "translate-x-6" : "translate-x-1"}`} />
      </button>
    </div>
  );
}

// ── Device status badge ───────────────────────────────────────────────
function DeviceStatusBadge({ status }: { status: DeviceInfo["status"] }) {
  const map: Record<DeviceInfo["status"], { tone: "success" | "info" | "warning" | "critical" | "default"; label: string }> = {
    paired:       { tone: "success", label: "Paired"        },
    connected:    { tone: "success", label: "Connected"     },
    pending:      { tone: "info",    label: "Pending"       },
    disconnected: { tone: "warning", label: "Disconnected"  },
    revoked:      { tone: "critical",label: "Revoked"       },
  };
  const { tone, label } = map[status] ?? { tone: "default", label: status };
  return <Badge tone={tone}>{label}</Badge>;
}

// ── Device type icon ──────────────────────────────────────────────────
function DeviceIcon({ type }: { type: string }) {
  const cls = "size-5 shrink-0 text-muted-foreground";
  if (type === "mobile")  return <Smartphone className={cls} />;
  if (type === "server")  return <Server className={cls} />;
  if (type === "laptop")  return <Laptop className={cls} />;
  return <Monitor className={cls} />;
}

// ══════════════════════════════════════════════════════════════════════
// DEVICE PAIRING PANEL
// ══════════════════════════════════════════════════════════════════════
function DevicePairingPanel() {
  const qc = useQueryClient();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  // ── State ─────────────────────────────────────────────────────────
  const [pairingToken, setPairingToken] = useState<string | null>(null);
  const [deviceId,     setDeviceId]     = useState<string | null>(null);
  const [expiresAt,    setExpiresAt]    = useState<string | null>(null);
  const [countdown,    setCountdown]    = useState(0);
  const [newName,      setNewName]      = useState("My Device");
  const [newType,      setNewType]      = useState("desktop");
  const [showQR,       setShowQR]       = useState(false);
  const [copied,       setCopied]       = useState(false);

  // ── Load devices list ─────────────────────────────────────────────
  const { data: devData, isLoading } = useQuery({
    queryKey: ["devices"],
    queryFn:  listDevices,
    refetchInterval: 10_000,
  });

  const devices = devData?.devices ?? [];

  // ── Generate pairing token mutation ──────────────────────────────
  const genToken = useMutation({
    mutationFn: () => generatePairingToken(newName, newType),
    onSuccess: (data) => {
      setPairingToken(data.pairing_token);
      setDeviceId(data.device_id);
      setExpiresAt(data.expires_at);
      setCountdown(data.expires_in_seconds);
      setShowQR(false);
      void qc.invalidateQueries({ queryKey: ["devices"] });
      toast.success("Pairing token generated — valid for 15 minutes");
    },
    onError: (e) => toast.error(`Failed: ${String(e)}`),
  });

  // ── Revoke device mutation ────────────────────────────────────────
  const revoke = useMutation({
    mutationFn: (id: string) => revokeDevice(id),
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["devices"] });
      toast.success("Device revoked");
    },
    onError: (e) => toast.error(`Failed: ${String(e)}`),
  });

  // ── Countdown timer ───────────────────────────────────────────────
  useEffect(() => {
    if (!pairingToken || countdown <= 0) return;
    const t = setInterval(() => {
      setCountdown(c => {
        if (c <= 1) { setPairingToken(null); setDeviceId(null); clearInterval(t); return 0; }
        return c - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, [pairingToken, countdown]);

  // ── Generate QR code ──────────────────────────────────────────────
  useEffect(() => {
    if (!pairingToken || !showQR || !canvasRef.current) return;
    const BASE = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";
    const pairUrl = `${BASE}/api/auth/devices/pair?token=${pairingToken}`;
    QRCode.toCanvas(canvasRef.current, pairUrl, {
      width: 200, margin: 2,
      color: { dark: "#10b981", light: "#070d0b" },
    }).catch(() => {});
  }, [pairingToken, showQR]);

  // ── Copy token to clipboard ───────────────────────────────────────
  const copyToken = () => {
    if (!pairingToken) return;
    void navigator.clipboard.writeText(pairingToken);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast.success("Token copied to clipboard");
  };

  const fmtCountdown = (s: number) =>
    `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;

  return (
    <div className="flex flex-col gap-4">
      {/* ── Generate Token Section ────────────────────────────────── */}
      <Panel title="Connect a New Device" right={
        <Badge tone="info">{devices.filter(d => d.is_paired && !d.is_revoked).length} paired</Badge>
      }>
        <div className="flex flex-col gap-4">
          {/* Device info inputs */}
          <div className="flex gap-2">
            <div className="flex-1">
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Device Name</label>
              <input
                value={newName}
                onChange={e => setNewName(e.target.value)}
                placeholder="e.g. Office Laptop"
                className="w-full rounded-lg border border-[var(--hairline)] bg-white/4 px-3 py-2 text-sm outline-none focus:border-primary/50"
              />
            </div>
            <div>
              <label className="mb-1 block text-[0.7rem] text-muted-foreground">Type</label>
              <select
                value={newType}
                onChange={e => setNewType(e.target.value)}
                className="rounded-lg border border-[var(--hairline)] bg-[#0d1a15] px-3 py-2 text-sm outline-none focus:border-primary/50"
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

          {/* Token display */}
          {pairingToken && (
            <div className="rounded-xl border border-primary/20 bg-primary/5 p-4">
              <div className="mb-3 flex items-center justify-between">
                <p className="text-sm font-semibold text-primary">Pairing Token</p>
                <div className="flex items-center gap-1.5 font-mono text-xs text-muted-foreground">
                  <Clock className="size-3" />
                  <span className={countdown < 60 ? "text-[var(--critical)]" : ""}>
                    {fmtCountdown(countdown)}
                  </span>
                </div>
              </div>

              {/* Token value */}
              <div className="mb-3 flex items-center gap-2 rounded-lg border border-[var(--hairline)] bg-black/30 px-3 py-2.5">
                <code className="flex-1 break-all font-mono text-xs text-foreground">
                  {pairingToken}
                </code>
                <button onClick={copyToken}
                  className="shrink-0 rounded p-1 text-muted-foreground hover:text-primary transition-colors">
                  {copied ? <CheckCircle2 className="size-4 text-[var(--success)]" /> : <Copy className="size-4" />}
                </button>
              </div>

              {/* QR toggle */}
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setShowQR(v => !v)}
                  className="flex items-center gap-1.5 rounded-lg border border-[var(--hairline)] px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  <QrCode className="size-3.5" />
                  {showQR ? "Hide QR Code" : "Show QR Code"}
                </button>
                <p className="text-[0.65rem] text-muted-foreground">Single-use · Expires in {fmtCountdown(countdown)}</p>
              </div>

              {/* QR code canvas */}
              {showQR && (
                <div className="mt-3 flex flex-col items-center gap-2">
                  <canvas ref={canvasRef} className="rounded-xl" />
                  <p className="text-[0.65rem] text-muted-foreground">Scan with AISS mobile app or secondary device</p>
                </div>
              )}

              {/* Instructions */}
              <div className="mt-4 space-y-1.5 rounded-lg border border-[var(--hairline)] bg-black/20 p-3">
                <p className="font-mono text-[0.65rem] font-semibold uppercase tracking-widest text-muted-foreground">How to pair:</p>
                {[
                  "On the remote PC: install AISS and open Settings → Connect Device",
                  "Enter the token above or scan the QR code",
                  "The device will appear in your list below once paired",
                  "Token expires in 15 minutes and can only be used once",
                ].map((step, i) => (
                  <div key={i} className="flex items-start gap-2">
                    <span className="mt-0.5 flex size-4 shrink-0 items-center justify-center rounded-full bg-primary/20 font-mono text-[0.55rem] text-primary">{i + 1}</span>
                    <span className="text-[0.65rem] text-muted-foreground">{step}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </Panel>

      {/* ── Paired Devices List ───────────────────────────────────── */}
      <Panel title="Registered Devices" right={
        <button onClick={() => qc.invalidateQueries({ queryKey: ["devices"] })}
          className="p-1 text-muted-foreground hover:text-foreground transition-colors">
          <RefreshCw className="size-3.5" />
        </button>
      }>
        {isLoading ? (
          <div className="flex h-20 items-center justify-center">
            <div className="size-5 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          </div>
        ) : devices.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-8 text-center">
            <Wifi className="size-8 text-muted-foreground opacity-30" />
            <p className="text-sm text-muted-foreground">No devices paired yet</p>
            <p className="text-xs text-muted-foreground">Generate a token above to connect another PC</p>
          </div>
        ) : (
          <ul className="divide-y divide-[var(--hairline)]">
            {devices.map(d => (
              <li key={d.id} className="flex items-center gap-3 py-3 first:pt-0 last:pb-0">
                <DeviceIcon type={d.device_type} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="truncate text-sm font-medium">{d.device_name}</p>
                    <DeviceStatusBadge status={d.status} />
                  </div>
                  <p className="mt-0.5 truncate font-mono text-[0.62rem] text-muted-foreground">
                    {d.hostname ?? d.platform ?? d.device_type}
                    {d.last_seen_ip ? ` · ${d.last_seen_ip}` : ""}
                    {d.last_seen_at
                      ? ` · last seen ${new Date(d.last_seen_at).toLocaleString()}`
                      : d.paired_at
                      ? ` · paired ${new Date(d.paired_at).toLocaleString()}`
                      : ""}
                  </p>
                </div>
                {!d.is_revoked && (
                  <button
                    onClick={() => {
                      if (confirm(`Revoke "${d.device_name}"? It will lose access immediately.`)) {
                        revoke.mutate(d.id);
                      }
                    }}
                    className="shrink-0 rounded p-1.5 text-muted-foreground hover:text-[var(--critical)] transition-colors"
                    title="Revoke device"
                  >
                    <Trash2 className="size-4" />
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
      </Panel>

      {/* ── What happens when revoked ────────────────────────────── */}
      <div className="rounded-lg border border-[var(--hairline)] bg-white/2 px-4 py-3">
        <p className="text-[0.7rem] font-semibold text-muted-foreground mb-1.5">Security notes</p>
        <ul className="space-y-1">
          {[
            "Pairing tokens are cryptographically random, single-use, and expire after 15 minutes",
            "Revoking a device immediately invalidates its credentials — it cannot reconnect",
            "Each device gets its own credential — revoking one doesn't affect others",
            "All device connections are logged in the audit trail",
          ].map((t, i) => (
            <li key={i} className="flex items-start gap-2">
              <Shield className="mt-0.5 size-3 shrink-0 text-primary" />
              <span className="text-[0.65rem] text-muted-foreground">{t}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════
// MAIN SETTINGS PAGE
// ══════════════════════════════════════════════════════════════════════
function SettingsPage() {
  const [showWizard, setShowWizard] = useState(false);
  const [tab, setTab]               = useState<"general" | "devices" | "ai" | "apikeys">("general");
  const { data: wizard }            = useWizard();
  const { data: libData }           = useLibraries();
  const { data: llmData }           = useLLMProviders();
  const { online }                  = useBackendStatus();

  const completed = wizard?.completed ?? 0;
  const total     = wizard?.total_questions ?? 0;
  const pct       = total > 0 ? Math.round((completed / total) * 100) : 0;

  const TABS = [
    { id: "general",  label: "General" },
    { id: "devices",  label: "Devices & Pairing" },
    { id: "ai",       label: "AI & Integrations" },
    { id: "apikeys",  label: "API Keys" },
  ] as const;

  return (
    <div>
      <PageHeader
        title="Settings"
        subtitle="Policies, device pairing, AI providers and platform integrations"
        right={
          <ActionButton
            label="Config Wizard"
            tone="success"
            onClick={() => setShowWizard(true)}
          />
        }
      />

      {showWizard && <SetupWizard onClose={() => setShowWizard(false)} />}

      {/* Tab bar */}
      <div className="mb-4 flex gap-0.5 rounded-xl border border-[var(--hairline)] bg-black/20 p-1 w-fit">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`rounded-lg px-4 py-1.5 text-sm font-medium transition-all ${
              tab === t.id
                ? "bg-primary/15 text-primary border border-primary/30"
                : "text-muted-foreground hover:text-foreground"
            }`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Tab: General ─────────────────────────────────────────── */}
      {tab === "general" && (
        <div className="grid gap-4 xl:grid-cols-2">
          {/* Config progress */}
          <div className="xl:col-span-2 panel p-4">
            <div className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-medium">AISS Configuration</p>
                <p className="mt-0.5 text-xs text-muted-foreground">
                  {completed}/{total} settings configured ·{" "}
                  {llmData?.total_providers ? `${llmData.total_providers} LLM provider(s) active` : "No LLM providers"}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <div className="h-1.5 w-32 overflow-hidden rounded-full bg-white/8">
                  <div className="h-full rounded-full bg-primary transition-all" style={{ width: `${pct}%` }} />
                </div>
                <span className="font-mono text-xs text-muted-foreground">{pct}%</span>
                <Badge tone={online ? "success" : "critical"}>{online ? "online" : "offline"}</Badge>
              </div>
            </div>
          </div>

          <Panel className="p-4" title="Auto-Response Policy">
            <Toggle label="Isolate host on critical detection" hint="Network-quarantines the endpoint within 5 seconds" initial />
            <Toggle label="Auto-block malicious IPs"          hint="Pushes deny rules to perimeter firewalls"         initial />
            <Toggle label="Disable compromised accounts"      hint="Requires Tier 3 approval for privileged accounts" initial />
            <Toggle label="Auto-rollback ransomware changes"  hint="Restores affected files from immutable snapshots" initial={false} />
          </Panel>

          <Panel className="p-4" title="Detection Tuning">
            <Toggle label="Behavioural analytics"     hint="UEBA baseline over 30 days"                    initial />
            <Toggle label="Threat intel enrichment"   hint="STIX/TAXII feeds, refreshed every 6h"          initial />
            <Toggle label="Low-confidence alerts"     hint="Surface detections below 70% model confidence" initial={false} />
            <Toggle label="Online ML anomaly scoring" hint="River HalfSpaceTrees — adapts to live traffic"  initial />
          </Panel>

          <div className="xl:col-span-2">
            <ModuleHealth />
          </div>
        </div>
      )}

      {/* ── Tab: Devices ─────────────────────────────────────────── */}
      {tab === "devices" && <DevicePairingPanel />}

      {/* ── Tab: AI & Integrations ───────────────────────────────── */}
      {tab === "ai" && (
        <div className="grid gap-4 xl:grid-cols-2">
          <Panel className="p-4" title="AI / LLM Providers">
            {llmData?.providers.length ? (
              <ul className="space-y-2">
                {llmData.providers.map(p => (
                  <li key={p} className="flex items-center gap-2">
                    <span className="size-2 rounded-full bg-[var(--success)]" />
                    <span className="text-sm">{p}</span>
                    <Badge tone="success">active</Badge>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">No LLM providers configured.</p>
                <p className="text-xs text-muted-foreground">Add ANTHROPIC_API_KEY, OPENAI_API_KEY, or GROQ_API_KEY to .env to enable AI analysis.</p>
                <ActionButton label="Open Config Wizard" tone="success" onClick={() => setShowWizard(true)} />
              </div>
            )}
          </Panel>

          <Panel className="p-4" title="Library Integrations">
            {libData ? (
              <div className="space-y-2">
                <div className="flex gap-2">
                  <Badge tone="success">{libData.enabled} enabled</Badge>
                  <Badge tone="warning">{libData.disabled} disabled</Badge>
                </div>
                <div className="h-1.5 w-full overflow-hidden rounded-full bg-white/8">
                  <div className="h-full rounded-full bg-primary"
                    style={{ width: `${Math.round((libData.enabled / Math.max(libData.total, 1)) * 100)}%` }} />
                </div>
                <p className="text-xs text-muted-foreground">
                  {Math.round((libData.enabled / Math.max(libData.total, 1)) * 100)}% of {libData.total} libraries active.
                </p>
              </div>
            ) : (
              <p className="text-xs text-muted-foreground">Connect to backend to view.</p>
            )}
          </Panel>
        </div>
      )}

      {/* ── Tab: API Keys ──────────────────────────────────────── */}
      {tab === "apikeys" && <ApiKeysTab />}
    </div>
  );
}

// ── API Keys Tab Component ────────────────────────────────────────────
function ApiKeysTab() {
  const { data, refetch, isLoading } = useQuery({
    queryKey: ["systemConfig"],
    queryFn: getSystemConfig,
    staleTime: 30_000,
  });
  const queryClient = useQueryClient();

  const [edits, setEdits] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);

  const handleSave = async () => {
    if (Object.keys(edits).length === 0) return;
    setSaving(true);
    try {
      const result = await updateSystemConfig(edits);
      toast.success(result.message);
      setEdits({});
      void queryClient.invalidateQueries({ queryKey: ["systemConfig"] });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save config");
    } finally {
      setSaving(false);
    }
  };

  const categories: Record<string, string[]> = {
    "Threat Intelligence": ["VIRUSTOTAL_API_KEY", "SHODAN_API_KEY", "CENSYS_API_ID", "CENSYS_API_SECRET"],
    "AI / LLM Providers":  ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GROQ_API_KEY", "GOOGLE_API_KEY", "OPENROUTER_API_KEY"],
    "GeoIP":               ["MAXMIND_LICENSE_KEY"],
    "Email":               ["MAIL_PASSWORD"],
  };

  const modelKeys = ["ANTHROPIC_MODEL", "OPENAI_MODEL", "GROQ_MODEL", "GEMINI_MODEL", "OPENROUTER_MODEL", "SPACY_MODEL", "SBERT_MODEL"];

  if (isLoading) {
    return <div className="flex items-center gap-2 text-muted-foreground"><RefreshCw className="size-4 animate-spin" /> Loading configuration...</div>;
  }

  if (!data) {
    return <p className="text-sm text-muted-foreground">Unable to load configuration. Ensure you are logged in as admin.</p>;
  }

  return (
    <div className="space-y-4">
      {Object.entries(categories).map(([cat, keys]) => (
        <Panel key={cat} className="p-4" title={cat}>
          <div className="space-y-3">
            {keys.map((key) => {
              const cfg = data.config[key];
              return (
                <div key={key} className="grid grid-cols-[200px_1fr] items-center gap-3">
                  <label className="font-mono text-xs text-muted-foreground">{key}</label>
                  <input
                    type="password"
                    defaultValue={cfg?.value ?? ""}
                    placeholder={cfg?.masked ? "(masked)" : "Enter value..."}
                    onChange={(e) => {
                      if (e.target.value) setEdits((prev) => ({ ...prev, [key]: e.target.value }));
                      else { const { [key]: _, ...rest } = edits; setEdits(rest); }
                    }}
                    className="rounded-lg border border-[var(--hairline)] bg-white/4 px-3 py-1.5 text-sm outline-none transition focus:border-primary/50"
                  />
                </div>
              );
            })}
          </div>
        </Panel>
      ))}

      <Panel className="p-4" title="Model Configuration">
        <div className="space-y-3">
          {modelKeys.map((key) => {
            const cfg = data.config[key];
            return (
              <div key={key} className="grid grid-cols-[200px_1fr] items-center gap-3">
                <label className="font-mono text-xs text-muted-foreground">{key}</label>
                <input
                  type="text"
                  defaultValue={cfg?.value ?? ""}
                  placeholder="Enter value..."
                  onChange={(e) => {
                    if (e.target.value) setEdits((prev) => ({ ...prev, [key]: e.target.value }));
                    else { const { [key]: _, ...rest } = edits; setEdits(rest); }
                  }}
                  className="rounded-lg border border-[var(--hairline)] bg-white/4 px-3 py-1.5 text-sm outline-none transition focus:border-primary/50"
                />
              </div>
            );
          })}
        </div>
      </Panel>

      <div className="flex items-center gap-3">
        <button
          onClick={() => void handleSave()}
          disabled={saving || Object.keys(edits).length === 0}
          className="flex items-center gap-2 rounded-lg border border-primary/40 bg-primary/15 px-5 py-2 text-sm font-semibold text-primary transition hover:bg-primary/25 disabled:opacity-40"
        >
          {saving ? <RefreshCw className="size-4 animate-spin" /> : <Save className="size-4" />}
          {saving ? "Saving..." : `Save Changes (${Object.keys(edits).length})`}
        </button>
        {Object.keys(edits).length > 0 && (
          <button onClick={() => setEdits({})} className="rounded-lg px-3 py-2 text-sm text-muted-foreground hover:text-foreground transition">
            Discard
          </button>
        )}
      </div>
    </div>
  );
}
