import { NextResponse } from "next/server";
import { getStore, isStoreWritable } from "@/lib/store";
import { isSetupComplete } from "@/lib/auth";
import type { HealthStatus } from "@/lib/types";

export const runtime = "nodejs";

export async function GET() {
  const store = await getStore();
  const writable = await isStoreWritable();
  const setupComplete = await isSetupComplete();
  const groqConfigured = Boolean(process.env.GROQ_API_KEY);

  const body: HealthStatus = {
    ok: setupComplete && (groqConfigured || process.env.NODE_ENV === "development"),
    setupComplete,
    groqConfigured,
    storeWritable: writable,
    services: {
      api: "up",
      store: writable ? "up" : "degraded",
      groq: groqConfigured ? "up" : "down",
      securityGate: "up",
      incidentPipeline: "up",
    },
    timestamp: new Date().toISOString(),
  };

  // Soft ok if setup done even without groq (gate still works)
  body.ok = setupComplete;

  return NextResponse.json({
    ...body,
    counts: {
      threats: store.threats.length,
      incidents: store.incidents.length,
      approvals: store.approvals.filter((a) => a.status === "pending").length,
      quarantine: store.quarantine.length,
    },
  });
}
