import { NextResponse } from "next/server";
import { z } from "zod";
import { getStore, updateStore } from "@/lib/store";
import { createSession, hashPassword, setSessionCookie } from "@/lib/auth";

export const runtime = "nodejs";

const schema = z.object({
  organizationName: z.string().min(2).max(80),
  adminEmail: z.string().email(),
  adminPassword: z.string().min(8).max(128),
  autoRemediateLowMedium: z.boolean().optional(),
  requireApprovalHighCritical: z.boolean().optional(),
});

export async function GET() {
  const store = await getStore();
  return NextResponse.json({
    setupComplete: Boolean(store.config?.setupComplete) || process.env.AISS_SETUP_COMPLETE === "true",
    groqConfigured: Boolean(process.env.GROQ_API_KEY),
    organizationName: store.config?.organizationName || null,
  });
}

export async function POST(req: Request) {
  const store = await getStore();
  if (store.config?.setupComplete) {
    return NextResponse.json({ error: "Setup already completed" }, { status: 400 });
  }

  const body = await req.json();
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  }

  const data = parsed.data;
  const passwordHash = await hashPassword(data.adminPassword);

  await updateStore((s) => {
    s.config = {
      setupComplete: true,
      adminEmail: data.adminEmail.toLowerCase(),
      adminPasswordHash: passwordHash,
      organizationName: data.organizationName,
      createdAt: new Date().toISOString(),
      autoRemediateLowMedium: data.autoRemediateLowMedium ?? true,
      requireApprovalHighCritical: data.requireApprovalHighCritical ?? true,
    };
    s.audit.unshift({
      id: `aud_${Date.now()}`,
      at: new Date().toISOString(),
      actor: data.adminEmail,
      action: "SETUP_COMPLETE",
      detail: data.organizationName,
    });
  });

  const token = await createSession({ email: data.adminEmail.toLowerCase(), role: "admin" });
  await setSessionCookie(token);

  return NextResponse.json({
    ok: true,
    message: "AISS setup complete. Security Gate and incident pipeline are live.",
    groqConfigured: Boolean(process.env.GROQ_API_KEY),
    hint: process.env.GROQ_API_KEY
      ? undefined
      : "Set GROQ_API_KEY in Vercel/env for AI Security Reasoning Layer.",
  });
}
