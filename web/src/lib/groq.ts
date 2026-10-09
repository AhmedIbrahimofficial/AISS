import Groq from "groq-sdk";
import { SECURITY_TOOLS, executeTool } from "./tools";
import { updateStore } from "./store";
import { uid } from "./utils";

const SYSTEM_PROMPT = `You are the AISS Security Reasoning Layer — an autonomous SOC analyst AI.

Your job:
1. Analyze threats: origin, behavior, affected assets, blast radius.
2. Use tools to inspect artifacts, list threats/incidents, manage quarantine and approvals.
3. Recommend clear actions: ALLOW, HOLD, QUARANTINE, or BLOCK.
4. For HIGH/CRITICAL impact actions, prefer approval gates — never invent approvals.
5. After containment, explain Verify and Learn outcomes.

Rules (non-negotiable):
- Only call tools that exist in the catalogue.
- Never fabricate IOCs, IPs, hashes, or findings.
- Never expose API keys, passwords, or secrets.
- Be concise, precise, and operational.
- When the user asks to scan/inspect something, call inspect_artifact.
- When asked about current posture, call get_health and list_threats.`;

export function getGroqClient(): Groq | null {
  const key = process.env.GROQ_API_KEY;
  if (!key) return null;
  return new Groq({ apiKey: key });
}

export function groqModel(): string {
  return process.env.GROQ_MODEL || "llama-3.3-70b-versatile";
}

export async function runSecurityAgent(
  userMessage: string,
  actorEmail = "admin",
): Promise<{ reply: string; toolsUsed: string[] }> {
  const client = getGroqClient();
  if (!client) {
    return {
      reply:
        "Groq is not configured. Set GROQ_API_KEY in environment (or complete setup) to enable the Security Reasoning Layer.",
      toolsUsed: [],
    };
  }

  type Msg = {
    role: "system" | "user" | "assistant" | "tool";
    content: string | null;
    tool_calls?: Array<{
      id: string;
      type: "function";
      function: { name: string; arguments: string };
    }>;
    tool_call_id?: string;
    name?: string;
  };

  const messages: Msg[] = [
    { role: "system", content: SYSTEM_PROMPT },
    { role: "user", content: userMessage },
  ];

  const toolsUsed: string[] = [];
  let finalText = "";

  for (let round = 0; round < 6; round++) {
    const completion = await client.chat.completions.create({
      model: groqModel(),
      messages: messages as never,
      tools: SECURITY_TOOLS as never,
      tool_choice: "auto",
      temperature: 0.2,
      max_tokens: 2048,
    });

    const choice = completion.choices[0]?.message;
    if (!choice) break;

    const toolCalls = choice.tool_calls || [];
    if (toolCalls.length === 0) {
      finalText = choice.content || "";
      break;
    }

    messages.push({
      role: "assistant",
      content: choice.content || null,
      tool_calls: toolCalls.map((tc) => ({
        id: tc.id,
        type: "function" as const,
        function: {
          name: tc.function.name,
          arguments: tc.function.arguments,
        },
      })),
    });

    for (const tc of toolCalls) {
      toolsUsed.push(tc.function.name);
      let args: Record<string, unknown> = {};
      try {
        args = JSON.parse(tc.function.arguments || "{}");
      } catch {
        args = {};
      }
      const result = await executeTool(tc.function.name, args, actorEmail);
      messages.push({
        role: "tool",
        tool_call_id: tc.id,
        name: tc.function.name,
        content: JSON.stringify(result).slice(0, 12000),
      });
    }
  }

  if (!finalText) {
    finalText = "Completed tool runs. Ask me to summarize findings if needed.";
  }

  await updateStore((s) => {
    s.chatHistory.push(
      { id: uid("msg"), role: "user", content: userMessage, at: new Date().toISOString() },
      {
        id: uid("msg"),
        role: "assistant",
        content: finalText,
        at: new Date().toISOString(),
        toolsUsed,
      },
    );
    if (s.chatHistory.length > 200) s.chatHistory = s.chatHistory.slice(-200);
  });

  return { reply: finalText, toolsUsed };
}

export async function quickAiRiskNote(context: string): Promise<string | undefined> {
  const client = getGroqClient();
  if (!client) return undefined;
  try {
    const completion = await client.chat.completions.create({
      model: groqModel(),
      messages: [
        {
          role: "system",
          content:
            "You are a concise malware/SOC analyst. In 2-3 sentences: origin hypothesis, behavior, recommended gate decision (ALLOW/HOLD/QUARANTINE/BLOCK).",
        },
        { role: "user", content: context.slice(0, 6000) },
      ],
      temperature: 0.1,
      max_tokens: 300,
    });
    return completion.choices[0]?.message?.content || undefined;
  } catch {
    return undefined;
  }
}
