import { NextResponse } from "next/server";
import { z } from "zod";
import { getStore, updateStore } from "@/lib/store";
import {
  createSession,
  setSessionCookie,
  verifyPassword,
} from "@/lib/auth";
import { uid } from "@/lib/utils";

export const runtime = "nodejs";

const schema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export async function POST(req: Request) {
  const body = await req.json();
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Invalid credentials payload" }, { status: 400 });
  }

  const store = await getStore();
  const config = store.config;
  if (!config?.setupComplete) {
    return NextResponse.json({ error: "Complete one-time setup first", setupRequired: true }, { status: 403 });
  }

  const email = parsed.data.email.toLowerCase();
  if (email !== config.adminEmail.toLowerCase()) {
    return NextResponse.json({ error: "Invalid email or password" }, { status: 401 });
  }

  const ok = await verifyPassword(parsed.data.password, config.adminPasswordHash);
  if (!ok) {
    return NextResponse.json({ error: "Invalid email or password" }, { status: 401 });
  }

  const token = await createSession({ email, role: "admin" });
  await setSessionCookie(token);

  await updateStore((s) => {
    s.audit.unshift({
      id: uid("aud"),
      at: new Date().toISOString(),
      actor: email,
      action: "LOGIN",
      detail: "success",
    });
  });

  return NextResponse.json({ ok: true, email, role: "admin" });
}
