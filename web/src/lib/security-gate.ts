import { createHash } from "crypto";
import type {
  GateInspectRequest,
  GateResult,
  GateStageResult,
  RiskLevel,
} from "./types";
import { decisionFromScore, riskLevelFromScore, uid } from "./utils";
import { getStore, updateStore } from "./store";
import { runIncidentPipeline } from "./pipeline";

const SUSPICIOUS_EXTS = [
  ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".apk",
];
const MALWARE_STRINGS = [
  "eicar",
  "powershell -enc",
  "invoke-mimikatz",
  "frombase64string",
  "cmd.exe /c",
  "wget http",
  "curl http",
  "reverse shell",
  "meterpreter",
  "createobject(\"wscript.shell\")",
  "document.write(unescape",
];
const BAD_DOMAINS = [
  "malware.test",
  "evil.example",
  "phishing-login.net",
  "ransom-pay.io",
  "crypto-drain.xyz",
];
const BAD_IPS = ["185.220.101.", "45.33.32.", "198.51.100.", "203.0.113."];

function sha256(input: string): string {
  return createHash("sha256").update(input).digest("hex");
}

function entropy(s: string): number {
  if (!s) return 0;
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
  let e = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    e -= p * Math.log2(p);
  }
  return e;
}

function push(
  stages: GateStageResult[],
  id: string,
  label: string,
  status: GateStageResult["status"],
  detail: string,
  scoreDelta: number,
) {
  stages.push({ id, label, status, detail, scoreDelta });
}

export async function inspectThroughGate(
  req: GateInspectRequest,
  options?: { runAi?: boolean; aiAnalysis?: string },
): Promise<GateResult> {
  const stages: GateStageResult[] = [];
  let score = 0;
  const indicators: string[] = [];
  const blockedReasons: string[] = [];
  const allowedReasons: string[] = [];

  // 1. Auth / intake
  push(stages, "intake", "Intake Validation", "pass", "Payload accepted for inspection", 0);

  // 2. Input validation
  const hasPayload =
    Boolean(req.content) ||
    Boolean(req.hash) ||
    Boolean(req.ip) ||
    Boolean(req.url) ||
    Boolean(req.processName) ||
    Boolean(req.name);
  if (!hasPayload) {
    push(stages, "input", "Input Validation", "fail", "Empty inspection payload", 40);
    score += 40;
    blockedReasons.push("Empty payload");
  } else {
    push(stages, "input", "Input Validation", "pass", "Required fields present", 0);
  }

  const blob = [
    req.name || "",
    req.content || "",
    req.hash || "",
    req.url || "",
    req.ip || "",
    req.processName || "",
    req.cmdline || "",
  ]
    .join(" ")
    .toLowerCase();

  const contentHash = req.hash || (req.content ? sha256(req.content) : "");
  if (contentHash) indicators.push(`hash:${contentHash.slice(0, 16)}…`);

  // 3. Static inspection
  let staticDelta = 0;
  if (req.name) {
    const lower = req.name.toLowerCase();
    if (SUSPICIOUS_EXTS.some((ext) => lower.endsWith(ext))) {
      staticDelta += 15;
      indicators.push(`ext:${lower.split(".").pop()}`);
    }
    if (/\.(exe|dll)\.(txt|jpg|png)$/i.test(req.name)) {
      staticDelta += 35;
      indicators.push("double-extension");
      blockedReasons.push("Double extension masquerading");
    }
  }
  if (req.content) {
    const ent = entropy(req.content.slice(0, 50000));
    if (ent > 7.2) {
      staticDelta += 20;
      indicators.push(`high-entropy:${ent.toFixed(2)}`);
    }
    for (const sig of MALWARE_STRINGS) {
      if (blob.includes(sig)) {
        staticDelta += 30;
        indicators.push(`sig:${sig}`);
        blockedReasons.push(`Matched signature: ${sig}`);
      }
    }
    // EICAR
    if (blob.includes("eicar-standard-antivirus-test-file") || blob.includes("x5o!p%@ap")) {
      staticDelta += 90;
      indicators.push("eicar");
      blockedReasons.push("EICAR test malware signature");
    }
  }
  push(
    stages,
    "inspect",
    "Security Inspection",
    staticDelta >= 30 ? "fail" : staticDelta > 0 ? "warn" : "pass",
    staticDelta ? `Static risk +${staticDelta}` : "No static red flags",
    staticDelta,
  );
  score += staticDelta;

  // 4. Threat intel (local lists + learned rules)
  let intelDelta = 0;
  const store = await getStore();
  if (req.ip && BAD_IPS.some((p) => req.ip!.startsWith(p))) {
    intelDelta += 40;
    indicators.push(`bad-ip:${req.ip}`);
    blockedReasons.push("IP matches known hostile range");
  }
  if (req.url) {
    try {
      const host = new URL(req.url).hostname.toLowerCase();
      if (BAD_DOMAINS.some((d) => host.includes(d))) {
        intelDelta += 50;
        indicators.push(`bad-domain:${host}`);
        blockedReasons.push("Domain on blocklist");
      }
    } catch {
      intelDelta += 10;
      indicators.push("malformed-url");
    }
  }
  for (const rule of store.learnedRules) {
    if (blob.includes(rule.pattern.toLowerCase())) {
      intelDelta += rule.weight;
      indicators.push(`learned:${rule.pattern}`);
    }
  }
  push(
    stages,
    "intel",
    "Threat Intelligence",
    intelDelta >= 40 ? "fail" : intelDelta > 0 ? "warn" : "pass",
    intelDelta ? `Intel risk +${intelDelta}` : "No intel hits",
    intelDelta,
  );
  score += intelDelta;

  // 5. Behavioral / process-network heuristics
  let behaveDelta = 0;
  if (req.type === "process" || req.processName) {
    const p = (req.processName || "").toLowerCase();
    const cmd = (req.cmdline || "").toLowerCase();
    if (["powershell", "cmd", "wscript", "cscript", "mshta"].some((x) => p.includes(x))) {
      if (/ -enc |bypass|downloadstring|iex |invoke-expression/.test(cmd)) {
        behaveDelta += 45;
        indicators.push("suspicious-script-host");
        blockedReasons.push("Script host with suspicious cmdline");
      } else {
        behaveDelta += 10;
      }
    }
  }
  if (req.type === "network" || req.port) {
    const riskyPorts = [4444, 5555, 6666, 1337, 31337, 445, 3389];
    if (req.port && riskyPorts.includes(req.port)) {
      behaveDelta += 25;
      indicators.push(`risky-port:${req.port}`);
    }
  }
  push(
    stages,
    "behavior",
    "Behavior Heuristics",
    behaveDelta >= 30 ? "fail" : behaveDelta > 0 ? "warn" : "pass",
    behaveDelta ? `Behavior risk +${behaveDelta}` : "Behavior nominal",
    behaveDelta,
  );
  score += behaveDelta;

  // 6. Policy
  const riskLevel: RiskLevel = riskLevelFromScore(Math.min(100, score));
  let policyDelta = 0;
  if (store.config?.requireApprovalHighCritical && (riskLevel === "HIGH" || riskLevel === "CRITICAL")) {
    policyDelta += 5;
  }
  push(stages, "policy", "Policy Evaluation", "pass", `Policy applied for ${riskLevel}`, policyDelta);
  score = Math.min(100, score + policyDelta);

  // 7. AI analysis slot
  if (options?.aiAnalysis) {
    const aiBoost = /critical|ransomware|exfil|c2|command.?and.?control/i.test(options.aiAnalysis)
      ? 15
      : /suspicious|phishing|malware/i.test(options.aiAnalysis)
        ? 8
        : 0;
    score = Math.min(100, score + aiBoost);
    push(
      stages,
      "ai",
      "AI Risk Analysis",
      aiBoost ? "warn" : "pass",
      options.aiAnalysis.slice(0, 280),
      aiBoost,
    );
  } else {
    push(stages, "ai", "AI Risk Analysis", "skip", "AI analysis deferred / optional", 0);
  }

  const finalScore = Math.min(100, Math.max(0, score));
  const finalLevel = riskLevelFromScore(finalScore);
  let decision = decisionFromScore(finalScore);
  if (blockedReasons.some((r) => /eicar|double extension/i.test(r))) decision = "BLOCK";

  push(
    stages,
    "decision",
    "Security Decision",
    decision === "ALLOW" ? "pass" : decision === "HOLD" ? "warn" : "fail",
    `${decision} @ score ${finalScore} (${finalLevel})`,
    0,
  );

  if (decision === "ALLOW") allowedReasons.push("Below risk thresholds");
  if (decision === "HOLD") allowedReasons.push("Held for analyst review");

  const threatId = uid("thr");
  const title =
    req.name ||
    req.processName ||
    req.url ||
    req.ip ||
    req.hash?.slice(0, 12) ||
    `${req.type} inspection`;

  const summary = `${decision}: ${title} scored ${finalScore}/100 (${finalLevel})`;

  await updateStore((s) => {
    s.threats.unshift({
      id: threatId,
      createdAt: new Date().toISOString(),
      type: req.type,
      title,
      summary,
      riskScore: finalScore,
      riskLevel: finalLevel,
      decision,
      source: "security-gate",
      indicators,
      metadata: {
        ...req.metadata,
        stages,
        hash: contentHash || undefined,
      },
      quarantined: decision === "QUARANTINE" || decision === "BLOCK",
      blocked: decision === "BLOCK",
    });
    if (decision === "QUARANTINE" || decision === "BLOCK") {
      s.quarantine.unshift({
        id: uid("q"),
        threatId,
        at: new Date().toISOString(),
        name: title,
        reason: blockedReasons.join("; ") || summary,
      });
    }
    s.audit.unshift({
      id: uid("aud"),
      at: new Date().toISOString(),
      actor: "security-gate",
      action: `GATE_${decision}`,
      detail: summary,
    });
  });

  let incidentId: string | undefined;
  if (decision !== "ALLOW") {
    const incident = await runIncidentPipeline(threatId, {
      title,
      origin: req.type,
      behavior: indicators.join(", ") || "unknown",
      affectedAssets: [req.name || req.processName || req.ip || "endpoint"].filter(Boolean) as string[],
      aiAnalysis: options?.aiAnalysis,
    });
    incidentId = incident.id;
  }

  return {
    decision,
    riskScore: finalScore,
    riskLevel: finalLevel,
    stages,
    summary,
    indicators,
    threatId,
    incidentId,
    aiAnalysis: options?.aiAnalysis,
    blockedReasons,
    allowedReasons,
  };
}
