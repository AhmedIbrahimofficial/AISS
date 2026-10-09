export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type GateDecision = "ALLOW" | "HOLD" | "QUARANTINE" | "BLOCK";
export type IncidentStage =
  | "DETECT"
  | "ISOLATE"
  | "ANALYZE"
  | "CONTAIN"
  | "REMEDIATE"
  | "VERIFY"
  | "LEARN"
  | "CLOSED";

export type ApprovalStatus = "pending" | "approved" | "rejected";

export interface AppConfig {
  setupComplete: boolean;
  adminEmail: string;
  adminPasswordHash: string;
  organizationName: string;
  createdAt: string;
  autoRemediateLowMedium: boolean;
  requireApprovalHighCritical: boolean;
}

export interface SessionUser {
  email: string;
  role: "admin" | "analyst";
}

export interface ThreatEvent {
  id: string;
  createdAt: string;
  type: "file" | "process" | "network" | "url" | "hash" | "text";
  title: string;
  summary: string;
  riskScore: number;
  riskLevel: RiskLevel;
  decision: GateDecision;
  source: string;
  indicators: string[];
  metadata: Record<string, unknown>;
  quarantined: boolean;
  blocked: boolean;
}

export interface PipelineStep {
  stage: IncidentStage;
  status: "pending" | "running" | "done" | "skipped" | "failed" | "awaiting_approval";
  at?: string;
  detail?: string;
  actor?: "system" | "ai" | "human";
}

export interface Incident {
  id: string;
  threatId: string;
  title: string;
  createdAt: string;
  updatedAt: string;
  stage: IncidentStage;
  riskLevel: RiskLevel;
  riskScore: number;
  origin: string;
  behavior: string;
  affectedAssets: string[];
  recommendation: string;
  steps: PipelineStep[];
  aiAnalysis?: string;
  learned?: string;
  containmentActions: string[];
}

export interface ApprovalRequest {
  id: string;
  incidentId: string;
  action: string;
  reason: string;
  riskLevel: RiskLevel;
  status: ApprovalStatus;
  createdAt: string;
  resolvedAt?: string;
  resolvedBy?: string;
}

export interface AuditEntry {
  id: string;
  at: string;
  actor: string;
  action: string;
  detail: string;
}

export interface GateInspectRequest {
  type: "file" | "process" | "network" | "url" | "hash" | "text";
  name?: string;
  content?: string;
  hash?: string;
  ip?: string;
  url?: string;
  processName?: string;
  cmdline?: string;
  port?: number;
  metadata?: Record<string, unknown>;
}

export interface GateStageResult {
  id: string;
  label: string;
  status: "pass" | "fail" | "warn" | "skip";
  detail: string;
  scoreDelta: number;
}

export interface GateResult {
  decision: GateDecision;
  riskScore: number;
  riskLevel: RiskLevel;
  stages: GateStageResult[];
  summary: string;
  indicators: string[];
  threatId: string;
  incidentId?: string;
  aiAnalysis?: string;
  blockedReasons: string[];
  allowedReasons: string[];
}

export interface HealthStatus {
  ok: boolean;
  setupComplete: boolean;
  groqConfigured: boolean;
  storeWritable: boolean;
  services: Record<string, "up" | "down" | "degraded">;
  timestamp: string;
}
