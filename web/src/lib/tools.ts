import { inspectThroughGate } from "./security-gate";
import { getStore, updateStore } from "./store";
import { resolveApproval } from "./pipeline";
import { uid } from "./utils";
import type { GateInspectRequest } from "./types";

export const SECURITY_TOOLS = [
  {
    type: "function" as const,
    function: {
      name: "list_threats",
      description: "List recent security threats scored by the AISS Security Gate",
      parameters: {
        type: "object",
        properties: {
          limit: { type: "number", description: "Max items (default 10)" },
          minScore: { type: "number", description: "Minimum risk score filter" },
        },
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "list_incidents",
      description: "List active and recent incidents in the Detect→Learn pipeline",
      parameters: {
        type: "object",
        properties: {
          limit: { type: "number" },
          openOnly: { type: "boolean" },
        },
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "inspect_artifact",
      description:
        "Run the AISS Security Gate on a file name/content, URL, IP, hash, or process. Returns allow/hold/quarantine/block with risk score.",
      parameters: {
        type: "object",
        properties: {
          type: {
            type: "string",
            enum: ["file", "process", "network", "url", "hash", "text"],
          },
          name: { type: "string" },
          content: { type: "string" },
          hash: { type: "string" },
          ip: { type: "string" },
          url: { type: "string" },
          processName: { type: "string" },
          cmdline: { type: "string" },
          port: { type: "number" },
        },
        required: ["type"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_quarantine",
      description: "List quarantined / blocked artifacts",
      parameters: { type: "object", properties: { limit: { type: "number" } } },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "list_approvals",
      description: "List pending high-impact action approvals",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "resolve_approval",
      description: "Approve or reject a pending high-impact containment/remediation action",
      parameters: {
        type: "object",
        properties: {
          approvalId: { type: "string" },
          decision: { type: "string", enum: ["approved", "rejected"] },
        },
        required: ["approvalId", "decision"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_health",
      description: "Return AISS service health and configuration status",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "get_learned_rules",
      description: "Show rules AISS learned from past incidents",
      parameters: { type: "object", properties: {} },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "analyze_threat",
      description:
        "Deep-dive a threat by id: origin, behavior, affected assets, recommendation",
      parameters: {
        type: "object",
        properties: { threatId: { type: "string" } },
        required: ["threatId"],
      },
    },
  },
];

export async function executeTool(
  name: string,
  args: Record<string, unknown>,
  actorEmail = "ai-agent",
): Promise<unknown> {
  const store = await getStore();

  switch (name) {
    case "list_threats": {
      const limit = Number(args.limit ?? 10);
      const minScore = Number(args.minScore ?? 0);
      return store.threats
        .filter((t) => t.riskScore >= minScore)
        .slice(0, limit)
        .map((t) => ({
          id: t.id,
          title: t.title,
          decision: t.decision,
          riskScore: t.riskScore,
          riskLevel: t.riskLevel,
          createdAt: t.createdAt,
          indicators: t.indicators,
        }));
    }
    case "list_incidents": {
      const limit = Number(args.limit ?? 10);
      const openOnly = Boolean(args.openOnly);
      return store.incidents
        .filter((i) => (openOnly ? i.stage !== "CLOSED" : true))
        .slice(0, limit);
    }
    case "inspect_artifact": {
      const req = args as unknown as GateInspectRequest;
      return inspectThroughGate(req);
    }
    case "get_quarantine": {
      const limit = Number(args.limit ?? 20);
      return store.quarantine.slice(0, limit);
    }
    case "list_approvals": {
      return store.approvals.filter((a) => a.status === "pending");
    }
    case "resolve_approval": {
      return resolveApproval(
        String(args.approvalId),
        args.decision === "rejected" ? "rejected" : "approved",
        actorEmail,
      );
    }
    case "get_health": {
      return {
        setupComplete: Boolean(store.config?.setupComplete),
        groqConfigured: Boolean(process.env.GROQ_API_KEY),
        threats: store.threats.length,
        incidents: store.incidents.length,
        pendingApprovals: store.approvals.filter((a) => a.status === "pending").length,
        quarantine: store.quarantine.length,
        learnedRules: store.learnedRules.length,
      };
    }
    case "get_learned_rules": {
      return store.learnedRules.slice(0, 50);
    }
    case "analyze_threat": {
      const threat = store.threats.find((t) => t.id === args.threatId);
      if (!threat) return { error: "Threat not found" };
      const incident = store.incidents.find((i) => i.threatId === threat.id);
      return {
        threat,
        incident,
        origin: threat.type,
        behavior: threat.indicators,
        affectedAssets: incident?.affectedAssets || [],
        recommendation:
          incident?.recommendation ||
          (threat.decision === "BLOCK"
            ? "Keep blocked; hunt for related IOCs"
            : threat.decision === "QUARANTINE"
              ? "Keep quarantined; submit for malware analysis"
              : "Continue monitoring"),
      };
    }
    default:
      await updateStore((s) => {
        s.audit.unshift({
          id: uid("aud"),
          at: new Date().toISOString(),
          actor: actorEmail,
          action: "UNKNOWN_TOOL",
          detail: name,
        });
      });
      return { error: `Unknown tool: ${name}` };
  }
}
