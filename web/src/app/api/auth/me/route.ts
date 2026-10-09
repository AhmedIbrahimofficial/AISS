import { NextResponse } from "next/server";
import { getSession, isSetupComplete } from "@/lib/auth";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";

export async function GET() {
  const setupComplete = await isSetupComplete();
  const session = await getSession();
  const store = await getStore();
  return NextResponse.json({
    setupComplete,
    user: session,
    organizationName: store.config?.organizationName || null,
    groqConfigured: Boolean(process.env.GROQ_API_KEY),
  });
}
