/**
 * AISS Frontend — Backend API Client
 * Connects the dashboard to the AISS FastAPI backend.
 *
 * Base URL: VITE_AISS_API_URL env var (default: http://localhost:8000)
 * Auth:     JWT Bearer token stored in localStorage
 * WS:       WebSocket for real-time threat feed + wizard popups
 */

const BASE = (import.meta.env.VITE_AISS_API_URL as string | undefined) ?? "http://localhost:8000";
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

// ── Core fetch helper ─────────────────────────────────────────────────
async function apiFetch<T>(
  path: string,
  opts: RequestInit = {},
  skipAuth = false,
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(opts.headers as Record<string, string> | undefined),
  };
  const tok = getToken();
  if (tok && !skipAuth) headers["Authorization"] = `Bearer ${tok}`;

  const res = await fetch(`${BASE}${path}`, { ...opts, headers });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error((err as { error?: string }).error ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

// ── Auth ──────────────────────────────────────────────────────────────
export async function login(username: string, password: string) {
  const form = new URLSearchParams({ username, password });
  const data = await fetch(`${BASE}/api/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
  }).then((r) => r.json()) as {
    access_token: string; refresh_token: string;
    token_type: string; username: string; role: string;
  };
  setToken(data.access_token);
  localStorage.setItem("aiss_refresh_token", data.refresh_token ?? "");
  return data;
}

export function logout() {
  setToken(null);
  localStorage.removeItem("aiss_refresh_token");
}

export const getMe = () => apiFetch<{ username: string; role: string; email: string }>("/api/auth/me");

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

// ── Network ───────────────────────────────────────────────────────────
export const getNetworkConnections = () => apiFetch<{ connections: NetworkConnection[] }>("/api/network/connections");
export const getNetworkStats       = () => apiFetch<NetworkStats>("/api/network/stats");

// ── Network Topology ──────────────────────────────────────────────────
export const getTopologyMap = () => apiFetch<TopologyMap>("/api/topology/map");
export const getTopologySegments = () => apiFetch<{ segments: NetworkSegment[] }>("/api/topology/segments");
export const addTopologySegment = (cidr: string, type: string, label: string) =>
  apiFetch<{ segment: NetworkSegment }>("/api/topology/segments", {
    method: "POST", body: JSON.stringify({ cidr, type, label }),
  });
export const scanAllNetworks = () => apiFetch<{ results: Record<string, unknown>; total_hosts: number }>("/api/topology/scan", { method: "POST" });

// ── Remote Agents ─────────────────────────────────────────────────────
export const getAgents      = () => apiFetch<{ agents: Agent[]; stats: AgentStats }>("/api/agents/");
export const getAgentStats  = () => apiFetch<AgentStats>("/api/agents/stats");
export const getAgent       = (id: string) => apiFetch<Agent>(`/api/agents/${id}`);
export const getAgentThreats= (id: string) => apiFetch<{ threats: Threat[] }>(`/api/agents/${id}/threats`);
export const generateAgentToken = (label: string) =>
  apiFetch<{ token: string; label: string; usage: string }>("/api/agents/token/generate", {
    method: "POST", body: JSON.stringify({ label }),
  });
export const sendAgentCommand = (id: string, command: string, params: Record<string, unknown> = {}) =>
  apiFetch<{ sent: boolean }>(`/api/agents/${id}/command`, {
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
  apiFetch<{ response: string }>("/api/soc-chat", { method: "POST", body: JSON.stringify({ message }) });

// ── Kill Chain ────────────────────────────────────────────────────────
export const getKillChain = () => apiFetch<KillChainStatus>("/api/kill-chain/status");

// ── Dataset ───────────────────────────────────────────────────────────
export const getDatasetStatus = () => apiFetch<DatasetStatus>("/api/dataset/status");

// ── License ───────────────────────────────────────────────────────────
export const getLicenseInfo = () => apiFetch<LicenseInfo>("/api/agents/setup/questions");

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

  _ws = new WebSocket(`${WS_BASE}/ws`);

  _ws.onopen = () => {
    _ws!.send(JSON.stringify({ action: "auth", token: tok }));
  };

  _ws.onmessage = (e) => {
    try {
      const data = JSON.parse(e.data as string) as WSEvent;
      _wsCallbacks.forEach((cb) => cb(data));
    } catch { /* ignore */ }
  };

  _ws.onclose = () => {
    _ws = null;
    // Reconnect after 5s
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

export interface KillChainStatus {
  active_chains: number; chains: Array<{ id: string; stage: string; source: string }>;
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
