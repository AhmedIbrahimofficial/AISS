import { NextResponse } from "next/server";
import { z } from "zod";
import { getSession } from "@/lib/auth";
import { inspectThroughGate } from "@/lib/security-gate";
import { quickAiRiskNote } from "@/lib/groq";

export const runtime = "nodejs";

const schema = z.object({
  type: z.enum(["file", "process", "network", "url", "hash", "text"]),
  name: z.string().optional(),
  content: z.string().optional(),
  hash: z.string().optional(),
  ip: z.string().optional(),
  url: z.string().optional(),
  processName: z.string().optional(),
  cmdline: z.string().optional(),
  port: z.number().optional(),
  useAi: z.boolean().optional(),
  metadata: z.record(z.unknown()).optional(),
});

export async function POST(req: Request) {
  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const body = await req.json();
  const parsed = schema.safeParse(body);
  if (!parsed.success) {
    return NextResponse.json({ error: parsed.error.flatten() }, { status: 400 });
  }

  const data = parsed.data;
  let aiAnalysis: string | undefined;
  if (data.useAi !== false && process.env.GROQ_API_KEY) {
    aiAnalysis = await quickAiRiskNote(
      JSON.stringify({
        type: data.type,
        name: data.name,
        url: data.url,
        ip: data.ip,
        processName: data.processName,
        cmdline: data.cmdline,
        contentPreview: data.content?.slice(0, 2000),
        hash: data.hash,
      }),
    );
  }

  const result = await inspectThroughGate(data, { aiAnalysis });
  return NextResponse.json(result);
}
