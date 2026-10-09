/**
 * AISS Frontend — Backend API Client
 * Connects the dashboard to the AISS FastAPI backend.
 *
 * Base URL: VITE_AISS_API_URL env var (default: http://localhost:8000)
 * Auth:     JWT Bearer token stored in localStorage
 * WS:       WebSocket for real-time threat feed + wizard popups
 */

const BASE = (import.meta.env["VITE_AISS_API_URL"] as string | undefined) ?? "http://localhost:8000";
const WS_BASE = BASE.replace(/^http/, "ws");

// ── Token management ──────────────────────────────────────────────────
let _token: string | null = null;

export function setToken(t: string | null) {
  _token = t;
  if (t) localStorage.setItem("aiss_token", t);
  else localStorage.removeItem("aiss_token");
}

export function getToken(): string | null {
  if (!_token) _token = localStorage.getItem("aiss_token");
  return _token;
}

// ── Core fetch helper — auto-refreshes expired tokens silently ──────
async function apiFetch<T>(
  path: string,
  opts: RequestInit = {},
  skipAuth = false,
): Promise<T> {
  const makeHeaders = (): Record<string, string> => {
    const h: Record<string, string> = {
      "Content-Type": "application/json",
      ...(opts.headers as Record<string, string> | undefined),
    };
    const tok = getToken();
    if (tok && !skipAuth) h["Authorization"] = `Bearer ${tok}`;
    return h;
  };

  let res = await fetch(`${BASE}${path}`, { ...opts, headers: makeHeaders() });

  // Silent refresh on 401 — keeps the user logged in transparently
  if (res.status === 401 && !skipAuth) {
    const refreshed = await silentRefresh();
    if (refreshed) {
      // Retry with new token
      res = await fetch(`${BASE}${path}`, { ...opts, headers: makeHeaders() });
    }
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(formatApiError(err) || `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// Format FastAPI / backend error payloads into a readable string.
function formatApiError(payload: unknown): string {
  if (!payload || typeof payload !== "object") return "Request failed";
  const p = payload as Record<string, unknown>;

  if (typeof p["detail"] === "string") return p["detail"];

  if (Array.isArray(p["detail"])) {
    return p["detail"]
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object") {
          const err = item as Record<string, unknown>;
          const loc = Array.isArray(err["loc"]) ? err["loc"].join(".") : err["loc"];
          const msg = typeof err["msg"] === "string" ? err["msg"] : undefined;
          if (loc && msg) return `${loc}: ${msg}`;
          return msg ?? JSON.stringify(item);
        }
        return String(item);
      })
      .join("; ");
  }

  if (typeof p["error"] === "string") return p["error"];
  if (typeof p["message"] === "string") return p["message"];

  return JSON.stringify(payload);
}

// ── Auth ──────────────────────────────────────────────────────────────
export async function register(username: string, email: string, password: string, phone_number?: string) {
  const res = await fetch(`${BASE}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, email, password, phone_number }),
  });
  const data = (await res.json()) as {
    user_id?: string; username?: string; email?: string; message?: string;
  };
  if (!res.ok || !data.user_id) {
    throw new Error(formatApiError(data) || "Registration failed");
  }
  return data as { user_id: string; username: string; email: string; message: string };
}

export async function login(email: string, password: string) {
  const data = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  }).then((r) => r.json()) as {
    access_token: string; refresh_token: string;
    token_type: string; expires_in: number;
    must_change_password?: boolean;
  };
  if (!data.access_token) throw new Error((data as unknown as { detail?: string }).detail ?? "Login failed");
  setToken(data.access_token);
  localStorage.setItem("aiss_refresh_token", data.refresh_token ?? "");
  localStorage.setItem("aiss_onboarding_done", "1");
  startBackgroundRefresh();
  return data;
}

export function logout() {
  // Stop background refresh first
  stopBackgroundRefresh();
  // Revoke refresh token on backend
  const rt = localStorage.getItem("aiss_refresh_token");
  if (rt) {
    fetch(`${BASE}/api/auth/logout`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: rt }),
    }).catch(() => {});
  }
  setToken(null);
  localStorage.removeItem("aiss_refresh_token");
}

// Silently refresh the access token using the stored refresh token.
// Called automatically before each API request if the token is expiring.
let _refreshPromise: Promise<boolean> | null = null;
export async function silentRefresh(): Promise<boolean> {
  if (_refreshPromise) return _refreshPromise;
  const rt = localStorage.getItem("aiss_refresh_token");
  if (!rt) return false;
  _refreshPromise = fetch(`${BASE}/api/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: rt }),
  }).then(async (r) => {
    if (!r.ok) {
      // Only clear tokens on explicit auth failure (401/403), not network errors
      if (r.status === 401 || r.status === 403) {
        setToken(null); localStorage.removeItem("aiss_refresh_token");
      }
      return false;
    }
    const d = await r.json() as { access_token: string; refresh_token: string };
    setToken(d.access_token);
    localStorage.setItem("aiss_refresh_token", d.refresh_token);
    startBackgroundRefresh();
    return true;
  }).catch(() => false).finally(() => { _refreshPromise = null; });
  return _refreshPromise;
}

// ── Periodic background refresh (every 10 minutes) ──────────────────────
// Keeps the session alive even while the user is idle.
// This implements the "login once" behavior — session extends with each refresh.
let _bgRefreshInterval: ReturnType<typeof setInterval> | null = null;
export function startBackgroundRefresh() {
  if (_bgRefreshInterval) return;
  _bgRefreshInterval = setInterval(() => {
    if (localStorage.getItem("aiss_refresh_token")) {
      void silentRefresh();
    }
  }, 10 * 60 * 1000); // every 10 minutes
}
export function stopBackgroundRefresh() {
  if (_bgRefreshInterval) {
    clearInterval(_bgRefreshInterval);
    _bgRefreshInterval = null;
  }
}

// ── Onboarding ────────────────────────────────────────────────────────
export const getOnboardingStatus = () =>
  apiFetch<{ is_completed: boolean; completed_steps: string[]; completed_at: string | null }>("/api/auth/onboarding");

export const completeOnboarding = (completed_steps: string[] = []) =>
  apiFetch<{ status: string; completed_at: string }>("/api/auth/onboarding/complete", {
    method: "POST",
    body: JSON.stringify({ completed_steps }),
  });

// ── Device Pairing ────────────────────────────────────────────────────
export const generatePairingToken = (device_name: string, device_type = "desktop") =>
  apiFetch<{ device_id: string; pairing_token: string; expires_at: string; expires_in_seconds: number; instructions: string }>(
    "/api/auth/devices/pairing-token",
    { method: "POST", body: JSON.stringify({ device_name, device_type }) }
  );

export const listDevices = () =>
  apiFetch<{ devices: DeviceInfo[] }>("/api/auth/devices");

export const revokeDevice = (device_id: string, reason = "Revoked by user") =>
  apiFetch<{ status: string }>(`/api/auth/devices/${device_id}/revoke`, {
    method: "POST", body: JSON.stringify({ reason }),
  });

export interface DeviceInfo {
  id: string;
  device_name: string;
  device_type: string;
  platform: string | null;
  hostname: string | null;
  os_info: string | null;
  status: "pending" | "paired" | "connected" | "disconnected" | "revoked";
  is_paired: boolean;
  is_revoked: boolean;
  paired_at: string | null;
  last_seen_at: string | null;
  last_seen_ip: string | null;
  connection_count: number;
  created_at: string;
}

export const getMe = () => apiFetch<{ username: string; role: string; email: string; id: string; must_change_password?: boolean }>("/api/auth/me");

export const changePassword = (current_password: string, new_password: string) =>
  apiFetch<{ message: string }>("/api/auth/change-password", {
    method: "POST",
    body: JSON.stringify({ current_password, new_password }),
  });

export interface UserInfo {
  id: string;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  is_verified: boolean;
  created_at: string | null;
  last_login_at: string | null;
  last_login_ip: string | null;
  active_sessions: number;
}

export interface UsersResponse {
  users: UserInfo[];
  total: number;
  admin_count: number;
  active_count: number;
}

export const getUsers = () => apiFetch<UsersResponse>("/api/auth/users");

// ── System Config (API keys, settings) ─────────────────────────────────
export const getSystemConfig = () =>
  apiFetch<{ config: Record<string, { value: string; masked: boolean }>; sensitive_keys: string[] }>("/api/system/config");
export const updateSystemConfig = (updates: Record<string, string>) =>
  apiFetch<{ applied: number; message: string }>("/api/system/config", {
    method: "POST",
    body: JSON.stringify(updates),
  });

// ── Health ────────────────────────────────────────────────────────────
export const getHealth    = () => apiFetch<SystemHealth>("/api/health", {}, true);
export const getSystemHealth = () => apiFetch<SystemHealthDetail>("/api/system/health");
export const getLibraries = () => apiFetch<{ total: number; enabled: number; disabled: number; libraries: LibraryStatus[] }>("/api/system/libraries");
export const getLLMProviders = () => apiFetch<{ providers: string[]; total_providers: number }>("/api/system/llm-providers");
export const getSemanticStore = () => apiFetch<{ available: boolean; threat_count: number }>("/api/system/semantic-store");
export const getWizardQuestions = () => apiFetch<WizardData>("/api/system/wizard");
export const applyWizardAnswers = (answers: Record<string, string>) =>
  apiFetch<{ applied: number; message: string }>("/api/system/wizard/apply", { method: "POST", body: JSON.stringify(answers) });
export const submitPopupAnswer = (question_id: string, value: string) =>
  apiFetch<{ recorded: boolean }>("/api/system/popup-answer", {
    method: "POST",
    body: JSON.stringify({ question_id, value }),
  });

// ── Threats ───────────────────────────────────────────────────────────
export const getThreats       = () => apiFetch<{ threats: Threat[] }>("/api/threats/");
export const getActiveThreats = () => apiFetch<{ threats: Threat[] }>("/api/threats/active");
export const getThreatStats   = () => apiFetch<ThreatStats>("/api/threats/stats");
export const resolveThreat    = (id: string, note = "Resolved from dashboard") =>
  apiFetch<{ status: string }>(`/api/threats/${id}/resolve`, { method: "POST", body: JSON.stringify({ note }) });
export const exportThreatsExcel = () => fetch(`${BASE}/api/threats/export/excel`, { headers: { Authorization: `Bearer ${getToken() ?? ""}` } });
export const exportThreatsChart = () => fetch(`${BASE}/api/threats/export/chart.png`, { headers: { Authorization: `Bearer ${getToken() ?? ""}` } });
export const exportThreatsDashboard = () => fetch(`${BASE}/api/threats/export/dashboard.html`, { headers: { Authorization: `Bearer ${getToken() ?? ""}` } });

// ── Scanner ───────────────────────────────────────────────────────────
export const triggerScan = () => apiFetch<{ status: string }>("/api/scanner/scan", { method: "POST" });

// ── Live System (real PC data) ────────────────────────────────────────
export const getLiveProcesses    = () => apiFetch<LiveProcessData>("/api/live/processes");
export const getLiveFiles        = () => apiFetch<LiveFileData>("/api/live/files");
export const getLiveNetworkStats = () => apiFetch<LiveNetworkStats>("/api/live/network-stats");
export const getLiveDisk         = () => apiFetch<{ partitions: DiskPartition[] }>("/api/live/disk");

export const getNetworkStats     = () => getLiveNetworkStats(); // alias used by PacketVisualizer

// ── Network ───────────────────────────────────────────────────────────
export const getNetworkConnections = () => apiFetch<{ connections: NetworkConnection[] }>("/api/network/connections");

// ── Network Topology ──────────────────────────────────────────────────
export const getTopologyMap = () => apiFetch<TopologyMap>("/api/topology/map");
export const getTopologySegments = () => apiFetch<{ segments: NetworkSegment[] }>("/api/topology/segments");
export const addTopologySegment = (cidr: string, type: string, label: string) =>
  apiFetch<{ segment: NetworkSegment }>("/api/topology/segments", {
    method: "POST", body: JSON.stringify({ cidr, type, label }),
  });
export const scanAllNetworks = () => apiFetch<{ results: Record<string, unknown>; total_hosts: number }>("/api/topology/scan", { method: "POST" });

// ── Remote Agents ─────────────────────────────────────────────────────
export const getAgents      = () => apiFetch<{ agents: Agent[]; stats: AgentStats }>("/api/remote-agents/");
export const getAgentStats  = () => apiFetch<AgentStats>("/api/remote-agents/stats");
export const getAgent       = (id: string) => apiFetch<Agent>(`/api/remote-agents/${id}`);
export const getAgentThreats= (id: string) => apiFetch<{ threats: Threat[] }>(`/api/remote-agents/${id}/threats`);
export const generateAgentToken = (label: string) =>
  apiFetch<{ token: string; label: string; usage: string }>("/api/remote-agents/token/generate", {
    method: "POST", body: JSON.stringify({ label }),
  });
export const sendAgentCommand = (id: string, command: string, params: Record<string, unknown> = {}) =>
  apiFetch<{ sent: boolean }>(`/api/remote-agents/${id}/command`, {
    method: "POST", body: JSON.stringify({ command, params }),
  });

// ── Intelligence ──────────────────────────────────────────────────────
export const enrichIP       = (ip: string) => apiFetch<IPEnrichment>(`/api/intel/enrich/ip/${ip}`);
export const extractIOCs    = (text: string) => apiFetch<{ iocs: IOCResult }>("/api/intel/ioc/extract", { method: "POST", body: JSON.stringify({ text }) });
export const analyzePhishing= (url: string) => apiFetch<PhishingResult>("/api/intel/phishing/analyze", { method: "POST", body: JSON.stringify({ url }) });
export const semanticSearch = (query: string, n = 5) =>
  apiFetch<{ results: SemanticResult[]; count: number }>("/api/intel/semantic/search", { method: "POST", body: JSON.stringify({ query, n }) });
export const llmAnalyze     = (text: string) => apiFetch<{ analysis: Record<string, unknown> }>("/api/intel/llm/analyze", { method: "POST", body: JSON.stringify({ text }) });
export const scoreAnomaly   = (event: Record<string, number>) =>
  apiFetch<{ score: number; is_anomaly: boolean }>("/api/intel/anomaly/score", { method: "POST", body: JSON.stringify({ event }) });
export const getTaxiiStats  = () => apiFetch<{ configured: boolean; indicators_cached: number }>("/api/intel/taxii/stats");
export const ingestTaxii    = () => apiFetch<{ ingested: number }>("/api/intel/taxii/ingest", { method: "POST" });

// ── File Analysis ─────────────────────────────────────────────────────
export const analyzeFile = (file: File) => {
  const form = new FormData();
  form.append("file", file);
  return fetch(`${BASE}/api/files/analyze`, {
    method: "POST",
    headers: { Authorization: `Bearer ${getToken() ?? ""}` },
    body: form,
  }).then((r) => r.json()) as Promise<FileAnalysis>;
};

// ── AI Analysis ───────────────────────────────────────────────────────
export const aiAnalyzeThreat = (threatId: string) =>
  apiFetch<AIAnalysis>(`/api/ai/analyze/${threatId}`, { method: "POST" });

// ── SOC Chat ──────────────────────────────────────────────────────────
export const socChat = (message: string) =>
  apiFetch<{ response: string; provider: string; tool_calls: Array<{ tool: string; args: Record<string, unknown>; result: Record<string, unknown> }> }>("/api/soc-chat", { method: "POST", body: JSON.stringify({ message }) });

export const socChatV2 = (message: string, history: Array<{ role: string; text: string }> = []) =>
  apiFetch<{
    response: string;
    provider: string;
    tool_calls: Array<{ tool: string; args: Record<string, unknown>; result: Record<string, unknown> }>;
  }>("/api/soc-chat", { method: "POST", body: JSON.stringify({ message, history }) });

// ── Kill Chain ────────────────────────────────────────────────────────
export const getKillChain = () => apiFetch<KillChainStatus>("/api/kill-chain");

// ── Dataset ───────────────────────────────────────────────────────────
export const getDatasetStatus = () => apiFetch<DatasetStatus>("/api/dataset/status");

// ── License ───────────────────────────────────────────────────────────
export const getLicenseInfo = () => apiFetch<LicenseInfo>("/api/remote-agents/setup/questions");

// ── Security Orchestrator (Autonomous Scans) ────────────────────────
export const getSecurityTasks = (limit = 50) =>
  apiFetch<{ status: string; data: SecurityTaskSummary[] }>(`/api/security/tasks?limit=${limit}`);

export const getSecurityTask = (taskId: string) =>
  apiFetch<{ status: string; data: SecurityTaskDetail }>(`/api/security/tasks/${taskId}`);

export const cancelSecurityTask = (taskId: string) =>
  apiFetch<{ status: string; message: string }>(`/api/security/tasks/${taskId}/cancel`, { method: "POST" });

export const startSecurityScan = (opts: { description?: string; target_dirs?: string[]; eicar_test?: boolean } = {}) =>
  apiFetch<{ task_id: string; status: string; message: string }>("/api/security/full-scan", {
    method: "POST",
    body: JSON.stringify(opts),
  });

export const startEicarTest = () =>
  apiFetch<{ task_id: string; status: string; message: string }>("/api/security/eicar-test", { method: "POST" });

export const verifyPipeline = () =>
  apiFetch<{ status: string; data: PipelineVerificationResult }>("/api/security/verify-pipeline", { method: "POST" });

// ═════════════════════════════════════════════════════════════════════
// WebSocket client
// ═════════════════════════════════════════════════════════════════════

type WSCallback = (event: WSEvent) => void;
type WSEvent = {
  event: string;
  [key: string]: unknown;
};

let _ws: WebSocket | null = null;
let _wsCallbacks: WSCallback[] = [];
let _wsReconnectTimer: ReturnType<typeof setTimeout> | null = null;

export function onWSEvent(cb: WSCallback) {
  _wsCallbacks.push(cb);
  return () => { _wsCallbacks = _wsCallbacks.filter((c) => c !== cb); };
}

export function connectWS(): WebSocket | null {
  const tok = getToken();
  if (!tok) return null;
  if (_ws && _ws.readyState === WebSocket.OPEN) return _ws;
  if (_ws && (_ws.readyState === WebSocket.CONNECTING)) return _ws;

  _ws = new WebSocket(`${WS_BASE}/ws`);

  _ws.onopen = () => {
    // Re-read token at send time in case it was refreshed
    const freshTok = getToken();
    if (!freshTok) { _ws?.close(); return; }
    _ws!.send(JSON.stringify({ action: "auth", token: freshTok }));
  };

  _ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data as string) as WSEvent;
      // If auth failed, clear token and stop reconnecting
      if (data["error"] && String(data["error"]).toLowerCase().includes("invalid")) {
        setToken(null);
        _ws?.close();
        return;
      }
      _wsCallbacks.forEach((cb) => cb(data));
    } catch { /* ignore */ }
  };

  _ws.onclose = () => {
    _ws = null;
    // Only reconnect if we still have a valid token
    if (_wsReconnectTimer) clearTimeout(_wsReconnectTimer);
    _wsReconnectTimer = setTimeout(() => {
      if (getToken()) connectWS();
    }, 5000);
  };

  _ws.onerror = () => { _ws?.close(); };

  return _ws;
}

export function disconnectWS() {
  if (_wsReconnectTimer) clearTimeout(_wsReconnectTimer);
  _ws?.close();
  _ws = null;
}

export function sendWSMessage(action: string, payload: Record<string, unknown> = {}) {
  if (_ws?.readyState === WebSocket.OPEN) {
    _ws.send(JSON.stringify({ action, ...payload }));
  }
}

// ═════════════════════════════════════════════════════════════════════
// Types
// ═════════════════════════════════════════════════════════════════════

export interface Threat {
  id: string;
  type: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low";
  source: string;
  module: string;
  status: "active" | "analyzing" | "responding" | "resolved";
  detected_at: string;
  resolved_at?: string;
  resolution_note?: string;
  metadata?: Record<string, unknown>;
  ai_analysis?: string;
}

export interface ThreatStats {
  total: number;
  active: number;
  resolved: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface SystemHealth {
  status: string;
  modules: string[];
  platform: string;
}

export interface SystemHealthDetail {
  uptime_secs: number;
  cpu_percent: number;
  ram_percent: number;
  ram_used_mb: number;
  ram_total_mb: number;
  disk_percent: number;
  net_sent_mb: number;
  net_recv_mb: number;
  process_count: number;
  modules: Record<string, boolean>;
}

export interface LibraryStatus {
  name: string;
  enabled: boolean;
  version: string;
  notes: string;
}

export interface NetworkConnection {
  local_address: string;
  remote_address: string;
  status: string;
  pid?: number;
}

export interface NetworkStats {
  connections: number;
  blocked: number;
  throughput_mb: number;
}

export interface TopologyMap {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  segments: NetworkSegment[];
  generated_at: string;
  node_count: number;
  edge_count: number;
}

export interface TopologyNode {
  id: string;
  label: string;
  type: string;
  ip?: string;
  status: string;
  net_type?: string;
  is_center?: boolean;
  details?: Record<string, unknown>;
}

export interface TopologyEdge {
  source: string;
  target: string;
  label?: string;
}

export interface NetworkSegment {
  id: string;
  cidr: string;
  type: string;
  label: string;
  nodes: string[];
  agent_count: number;
}

export interface Agent {
  id: string;
  hostname: string;
  ip: string;
  os_name: string;
  status: string;
  network_type: string;
  cpu_percent: number;
  ram_percent: number;
  threat_count: number;
  connected_at: string;
  last_seen: string;
}

export interface AgentStats {
  total: number;
  connected: number;
  disconnected: number;
  by_network: { lan: number; wan: number; vpn: number; man: number };
  total_threats: number;
}

export interface IPEnrichment {
  ip: string;
  intel: { vt?: Record<string, unknown>; shodan?: Record<string, unknown>; risk_score: number };
  geo: { country_code: string; country_name: string; city: string; latitude: number; longitude: number };
}

export interface IOCResult {
  ips: string[]; domains: string[]; urls: string[];
  emails: string[]; hashes: string[]; cves: string[];
  mitre_techniques: string[]; malware_names: string[]; ports: string[];
}

export interface PhishingResult {
  url: string; risk_score: number; risk_level: string;
  flags: string[]; recommendation: string;
}

export interface SemanticResult {
  id: string; document: string; score: number;
  metadata: { type: string; severity: string; source: string };
}

export interface FileAnalysis {
  path: string; size_bytes: number; mime_type: string;
  entropy: number; threats: Array<{ type: string; detail: string }>;
  iocs: IOCResult; text?: string;
}

export interface AIAnalysis {
  threat_assessment: string; risk_level: string;
  attack_vector: string; immediate_actions: string[];
  mitre_tactics: string[]; recommended_response: string;
}

export interface KillChainStage {
  id: string;
  label: string;
  description: string;
  icon: string;
  color: string;
  threats: Threat[];
  total: number;
  active: number;
  critical: number;
  compromised: boolean;
}

export interface KillChainStatus {
  stages: KillChainStage[];
  total_threats: number;
  stages_compromised: number;
  attack_progress: number;
  graph: {
    nodes: Array<{ id: string; label: string; type: string; color?: string }>;
    edges: Array<{ source: string; target: string; relation: string }>;
    node_count: number;
    edge_count: number;
  };
}

export interface DatasetStatus {
  loaded: boolean; total_rows: number; patterns: Record<string, unknown>;
}

export interface LicenseInfo {
  license_type: string; status: string; organization: string;
  seats: number; features: Record<string, boolean>; expires_at?: string;
}

export interface WizardData {
  steps: Array<{ id: string; title: string; icon: string }>;
  questions_by_step: Record<string, WizardQuestion[]>;
  total_questions: number;
  completed: number;
}

export interface WizardQuestion {
  id: string; step: string; title: string; label: string;
  type: string; placeholder?: string; default?: string;
  required?: boolean; options?: Array<{ value: string; label: string }>;
  help_text?: string; help_url?: string; current_value?: string;
  icon?: string;
}

// ── Live System types ─────────────────────────────────────────────────
export interface LiveProcess {
  pid: number;
  name: string;
  user: string;
  cpu: number;
  mem: number;
  status: string;
  exe: string;
  cmd: string;
  started: number;
  suspicious: boolean;
}

export interface LiveProcessData {
  processes: LiveProcess[];
  total: number;
  suspicious_count: number;
}

export interface LiveFile {
  name: string;
  path: string;
  dir: string;
  size: number;
  ext: string;
  modified: number;
  risk: boolean;
}

export interface LiveFileData {
  files: LiveFile[];
  total_found: number;
  scanned_dirs: number;
  suspicious: LiveFile[];
  suspicious_count: number;
  dirs_scanned: string[];
}

export interface LiveNetworkStats {
  connections: number;
  listening: number;
  blocked: number;
  total_conns: number;
  throughput_mb: number;
  sent_mb_s: number;
  recv_mb_s: number;
  total_sent_mb: number;
  total_recv_mb: number;
  interfaces: Array<{ name: string; speed: number; mtu: number; up: boolean }>;
}

export interface DiskPartition {
  device: string;
  mountpoint: string;
  fstype: string;
  total_gb: number;
  used_gb: number;
  free_gb: number;
  percent: number;
}

// ── Security Orchestrator types ───────────────────────────────────────
export interface SecurityTaskSummary {
  id: string;
  status: string;
  description: string;
  created_at: string | null;
  completed_at: string | null;
  findings_count: number;
}

export interface SecurityTaskFinding {
  type: string;
  severity: string;
  title: string;
  description: string | null;
  affected_resource: string | null;
  created_at: string | null;
}

export interface SecurityTaskExecution {
  id: string;
  status: string;
  duration_seconds: number | null;
}

export interface SecurityTaskDetail {
  task_id: string;
  status: string;
  description: string;
  created_at: string | null;
  completed_at: string | null;
  error: string | null;
  eicar_verified: boolean | null;
  findings_count: number;
  findings: SecurityTaskFinding[];
  execution: SecurityTaskExecution | null;
}

export interface PipelineVerificationResult {
  verified: boolean;
  task_id: string;
  eicar_sha256: string;
  scanners_available: { yara: boolean; clamav: boolean };
  findings: SecurityTaskFinding[];
  error?: string;
}
