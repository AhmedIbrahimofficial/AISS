import type { Incident, IncidentStage, PipelineStep, RiskLevel } from "./types";
import { getStore, updateStore } from "./store";
import { uid } from "./utils";

const STAGES: IncidentStage[] = [
  "DETECT",
  "ISOLATE",
  "ANALYZE",
  "CONTAIN",
  "REMEDIATE",
  "VERIFY",
  "LEARN",
];

function baseSteps(): PipelineStep[] {
  return STAGES.map((stage) => ({ stage, status: "pending" as const }));
}

export async function runIncidentPipeline(
  threatId: string,
  opts: {
    title: string;
    origin: string;
    behavior: string;
    affectedAssets: string[];
    aiAnalysis?: string;
  },
): Promise<Incident> {
  const store = await getStore();
  const threat = store.threats.find((t) => t.id === threatId);
  const riskLevel: RiskLevel = threat?.riskLevel || "MEDIUM";
  const riskScore = threat?.riskScore || 50;
  const needsApproval =
    (store.config?.requireApprovalHighCritical ?? true) &&
    (riskLevel === "HIGH" || riskLevel === "CRITICAL");
  const auto =
    (store.config?.autoRemediateLowMedium ?? true) &&
    (riskLevel === "LOW" || riskLevel === "MEDIUM");

  const now = () => new Date().toISOString();
  const steps = baseSteps();
  const containmentActions: string[] = [];
  let stage: IncidentStage = "DETECT";
  let recommendation = "Monitor and review";
  let learned: string | undefined;

  const mark = (
    s: IncidentStage,
    status: PipelineStep["status"],
    detail: string,
    actor: PipelineStep["actor"] = "system",
  ) => {
    const step = steps.find((x) => x.stage === s)!;
    step.status = status;
    step.at = now();
    step.detail = detail;
    step.actor = actor;
  };

  // DETECT
  mark("DETECT", "done", `Threat ${threatId} detected via Security Gate`, "system");
  stage = "ISOLATE";

  // ISOLATE
  if (threat?.quarantined || threat?.decision === "BLOCK" || threat?.decision === "QUARANTINE") {
    mark("ISOLATE", "done", "Artifact isolated in quarantine vault", "system");
    containmentActions.push("quarantine");
  } else if (threat?.decision === "HOLD") {
    mark("ISOLATE", "done", "Held in inspection buffer (network/process pause simulated)", "system");
    containmentActions.push("hold");
  } else {
    mark("ISOLATE", "skipped", "No isolation required for ALLOW path");
  }
  stage = "ANALYZE";

  // ANALYZE
  const analysis =
    opts.aiAnalysis ||
    `Heuristic analysis: origin=${opts.origin}; behavior=${opts.behavior}; score=${riskScore}`;
  mark("ANALYZE", "done", analysis.slice(0, 400), opts.aiAnalysis ? "ai" : "system");
  stage = "CONTAIN";

  // CONTAIN
  if (needsApproval && !auto) {
    mark(
      "CONTAIN",
      "awaiting_approval",
      "High-impact containment requires human approval",
      "system",
    );
    recommendation = "Approve containment: block indicators, isolate asset, revoke sessions";
    const incidentId = uid("inc");
    const incident: Incident = {
      id: incidentId,
      threatId,
      title: opts.title,
      createdAt: now(),
      updatedAt: now(),
      stage: "CONTAIN",
      riskLevel,
      riskScore,
      origin: opts.origin,
      behavior: opts.behavior,
      affectedAssets: opts.affectedAssets,
      recommendation,
      steps,
      aiAnalysis: opts.aiAnalysis,
      containmentActions,
    };

    await updateStore((s) => {
      s.incidents.unshift(incident);
      s.approvals.unshift({
        id: uid("apr"),
        incidentId,
        action: "CONTAIN_AND_REMEDIATE",
        reason: `${riskLevel} incident requires approval before containment/remediation`,
        riskLevel,
        status: "pending",
        createdAt: now(),
      });
      s.audit.unshift({
        id: uid("aud"),
        at: now(),
        actor: "pipeline",
        action: "APPROVAL_REQUIRED",
        detail: incidentId,
      });
    });
    return incident;
  }

  mark("CONTAIN", "done", "Indicators blocked; asset segment isolated", "system");
  containmentActions.push("block-indicators", "segment-asset");
  recommendation = "Contained automatically based on policy";
  stage = "REMEDIATE";

  // REMEDIATE
  mark("REMEDIATE", "done", "Removed/quarantined artifact; revoked suspicious sessions", "system");
  containmentActions.push("remediate");
  stage = "VERIFY";

  // VERIFY
  mark("VERIFY", "done", "Re-scan clean; no residual indicators in scope", "system");
  stage = "LEARN";

  // LEARN
  const pattern = opts.behavior.split(",")[0]?.trim() || opts.title.toLowerCase().slice(0, 40);
  learned = `Raised weight for pattern "${pattern}" after confirmed ${riskLevel} event`;
  mark("LEARN", "done", learned, "system");
  stage = "CLOSED";

  const incident: Incident = {
    id: uid("inc"),
    threatId,
    title: opts.title,
    createdAt: now(),
    updatedAt: now(),
    stage: "CLOSED",
    riskLevel,
    riskScore,
    origin: opts.origin,
    behavior: opts.behavior,
    affectedAssets: opts.affectedAssets,
    recommendation,
    steps,
    aiAnalysis: opts.aiAnalysis,
    learned,
    containmentActions,
  };

  await updateStore((s) => {
    s.incidents.unshift(incident);
    if (pattern && pattern.length > 3) {
      const existing = s.learnedRules.find((r) => r.pattern === pattern);
      if (existing) existing.weight = Math.min(40, existing.weight + 5);
      else {
        s.learnedRules.unshift({
          id: uid("lrn"),
          pattern,
          weight: 8,
          at: now(),
          note: learned!,
        });
      }
    }
    s.audit.unshift({
      id: uid("aud"),
      at: now(),
      actor: "pipeline",
      action: "INCIDENT_CLOSED",
      detail: incident.id,
    });
  });

  return incident;
}

export async function resolveApproval(
  approvalId: string,
  decision: "approved" | "rejected",
  by: string,
): Promise<{ approval: unknown; incident?: Incident }> {
  const store = await getStore();
  const approval = store.approvals.find((a) => a.id === approvalId);
  if (!approval) throw new Error("Approval not found");
  if (approval.status !== "pending") throw new Error("Approval already resolved");

  const incident = store.incidents.find((i) => i.id === approval.incidentId);
  if (!incident) throw new Error("Incident not found");

  const now = new Date().toISOString();

  if (decision === "rejected") {
    await updateStore((s) => {
      const a = s.approvals.find((x) => x.id === approvalId)!;
      a.status = "rejected";
      a.resolvedAt = now;
      a.resolvedBy = by;
      const inc = s.incidents.find((x) => x.id === approval.incidentId)!;
      const step = inc.steps.find((x) => x.stage === "CONTAIN");
      if (step) {
        step.status = "failed";
        step.detail = "Containment rejected by operator";
        step.at = now;
        step.actor = "human";
      }
      inc.stage = "ANALYZE";
      inc.updatedAt = now;
      inc.recommendation = "Operator rejected auto-containment; manual follow-up required";
      s.audit.unshift({
        id: uid("aud"),
        at: now,
        actor: by,
        action: "APPROVAL_REJECTED",
        detail: approvalId,
      });
    });
    return { approval: { ...approval, status: "rejected" } };
  }

  // approved — continue CONTAIN → REMEDIATE → VERIFY → LEARN
  await updateStore((s) => {
    const a = s.approvals.find((x) => x.id === approvalId)!;
    a.status = "approved";
    a.resolvedAt = now;
    a.resolvedBy = by;
    const inc = s.incidents.find((x) => x.id === approval.incidentId)!;

    const finish = (stage: IncidentStage, detail: string) => {
      const step = inc.steps.find((x) => x.stage === stage)!;
      step.status = "done";
      step.detail = detail;
      step.at = now;
      step.actor = stage === "CONTAIN" ? "human" : "system";
    };

    finish("CONTAIN", `Containment approved by ${by}`);
    finish("REMEDIATE", "Remediation executed after approval");
    finish("VERIFY", "Verification scan clean");
    const pattern = inc.behavior.split(",")[0]?.trim() || inc.title.toLowerCase().slice(0, 40);
    const learned = `Learned from approved ${inc.riskLevel} incident: ${pattern}`;
    finish("LEARN", learned);
    inc.learned = learned;
    inc.stage = "CLOSED";
    inc.updatedAt = now;
    inc.containmentActions.push("approved-contain", "remediate", "verify");
    if (pattern && pattern.length > 3) {
      const existing = s.learnedRules.find((r) => r.pattern === pattern);
      if (existing) existing.weight = Math.min(40, existing.weight + 8);
      else {
        s.learnedRules.unshift({
          id: uid("lrn"),
          pattern,
          weight: 12,
          at: now,
          note: learned,
        });
      }
    }
    s.audit.unshift({
      id: uid("aud"),
      at: now,
      actor: by,
      action: "APPROVAL_APPROVED",
      detail: approvalId,
    });
  });

  const refreshed = await getStore();
  return {
    approval: refreshed.approvals.find((a) => a.id === approvalId),
    incident: refreshed.incidents.find((i) => i.id === approval.incidentId),
  };
}
