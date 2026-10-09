import { NextResponse } from "next/server";
import { getSession } from "@/lib/auth";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";

export async function GET() {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const store = await getStore();
  const openIncidents = store.incidents.filter((i) => i.stage !== "CLOSED");
  const pendingApprovals = store.approvals.filter((a) => a.status === "pending");

  const last24h = Date.now() - 24 * 60 * 60 * 1000;
  const recentThreats = store.threats.filter(
    (t) => new Date(t.createdAt).getTime() >= last24h,
  );

  const byDecision = {
    ALLOW: 0,
    HOLD: 0,
    QUARANTINE: 0,
    BLOCK: 0,
  };
  for (const t of store.threats) {
    byDecision[t.decision]++;
  }

  return NextResponse.json({
    organizationName: store.config?.organizationName,
    stats: {
      threatsTotal: store.threats.length,
      threats24h: recentThreats.length,
      openIncidents: openIncidents.length,
      pendingApprovals: pendingApprovals.length,
      quarantine: store.quarantine.length,
      learnedRules: store.learnedRules.length,
      blocked: byDecision.BLOCK,
      quarantined: byDecision.QUARANTINE,
      held: byDecision.HOLD,
      allowed: byDecision.ALLOW,
    },
    recentThreats: store.threats.slice(0, 12),
    openIncidents: openIncidents.slice(0, 8),
    pendingApprovals: pendingApprovals.slice(0, 8),
    audit: store.audit.slice(0, 15),
    groqConfigured: Boolean(process.env.GROQ_API_KEY),
  });
}
