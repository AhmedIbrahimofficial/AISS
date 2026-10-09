import { NextResponse } from "next/server";
import { z } from "zod";
import { getSession } from "@/lib/auth";
import { runSecurityAgent } from "@/lib/groq";
import { getStore } from "@/lib/store";

export const runtime = "nodejs";

const schema = z.object({
  message: z.string().min(1).max(8000),
});

export async function GET() {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const store = await getStore();
  return NextResponse.json({
    history: store.chatHistory.slice(-40),
    groqConfigured: Boolean(process.env.GROQ_API_KEY),
    model: process.env.GROQ_MODEL || "llama-3.3-70b-versatile",
  });
}

export async function POST(req: Request) {
  const session = await getSession();
  if (!session) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: "Message required" }, { status: 400 });
  }

  try {
    const result = await runSecurityAgent(parsed.data.message, session.email);
    return NextResponse.json(result);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "AI error";
    return NextResponse.json({ error: msg }, { status: 502 });
  }
}
