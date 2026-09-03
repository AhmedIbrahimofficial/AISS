"""AISS — SOC Agent (Agentic AI with Tool-Calling)

Gives the AI chat assistant the ability to execute real security operations
through natural language. Uses llm_router (OpenRouter) for all LLM calls.

Tools available:
  - run_scan, verify_pipeline, get_threats, get_threat_stats,
    resolve_threat, enrich_ip, get_system_health, get_scan_tasks,
    get_kill_chain, block_ip, run_nuclei_scan
"""
from __future__ import annotations

import json
import re
from typing import Any

from modules.llm_router import llm_router
from utils.logger import setup_logger

logger = setup_logger("soc_agent")

# ── Tool definitions for the LLM ────────────────────────────────────────

TOOL_DEFINITIONS = """
You have access to the following security tools. When the user asks you to perform
a security operation, respond with a JSON object containing a "tool_call" field:

{
  "tool_call": {
    "tool": "<tool_name>",
    "args": { ... }
  },
  "reasoning": "<brief explanation of why you're calling this tool>"
}

If the user is just asking a question (no action needed), respond normally without tool_call.

Available tools:
1. run_scan(description: str) - Start a full security scan. Args: {"description": "reason"}
2. verify_pipeline() - Run EICAR detection pipeline verification. Args: {}
3. get_threats(status: str) - Get threats. Args: {"status": "active" or "all"}
4. get_threat_stats() - Get threat statistics. Args: {}
5. resolve_threat(id: str, note: str) - Resolve/close a threat. Args: {"id": "threat-id", "note": "reason"}
6. enrich_ip(ip: str) - Enrich an IP with VirusTotal/Shodan. Args: {"ip": "x.x.x.x"}
7. get_system_health() - Get system health status. Args: {}
8. get_scan_tasks() - Get recent scan jobs. Args: {}
9. get_kill_chain() - Get kill chain status. Args: {}
10. block_ip(ip: str) - Block an IP via AI firewall. Args: {"ip": "x.x.x.x"}
11. run_nuclei_scan(target: str) - Start Nuclei vulnerability scan. Args: {"target": "ip or hostname"}

You can also respond with plain text for questions that don't require tool execution.
When you execute a tool, first return the tool_call JSON, then after seeing the result,
provide a human-readable summary.
"""

SOC_SYSTEM_PROMPT = (
    "You are AISS's AI SOC (Security Operations Center) Assistant with the ability to "
    "execute real security operations. You help analysts understand threats, run scans, "
    "enrich indicators, manage incidents, and monitor system health.\n\n"
    "Be concise and practical. Include CVE numbers when relevant. "
    "Give step-by-step mitigation guidance. "
    "Use severity ratings (CRITICAL/HIGH/MEDIUM/LOW). "
    "Never fabricate threat data or invent incidents.\n\n"
    f"{TOOL_DEFINITIONS}"
)


class SOCAgent:
    """Agentic SOC assistant that can execute security tools via LLM."""

    def __init__(self) -> None:
        pass

    def is_available(self) -> bool:
        return llm_router.is_available()

    async def chat(
        self,
        user_message: str,
        history: list[dict] | None = None,
        threat_engine: Any = None,
    ) -> dict:
        """
        Process a user message, potentially executing a tool call.

        Returns dict with keys: response, provider, tool_calls
        """
        # Build context from current system state
        context = await self._build_context(threat_engine)

        # Build messages
        messages: list[dict] = [{"role": "system", "content": SOC_SYSTEM_PROMPT}]

        # Add context as a system message
        if context:
            messages.append({"role": "system", "content": f"CURRENT SYSTEM STATE:\n{context}"})

        # Add conversation history
        if history:
            for h in history[-20:]:
                role = h.get("role", "user")
                content = h.get("text", h.get("content", ""))
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content})

        messages.append({"role": "user", "content": user_message})

        # Get LLM response
        reply = await llm_router.complete_messages(
            messages, max_tokens=1200, temperature=0.2,
        )

        # Check if the LLM wants to call a tool
        tool_call = self._parse_tool_call(reply)
        tool_calls_made: list[dict] = []

        if tool_call:
            tool_name = tool_call.get("tool", "")
            tool_args = tool_call.get("args", {})
            reasoning = tool_call.get("reasoning", "")

            # Execute the tool
            tool_result = await self._execute_tool(
                tool_name, tool_args, threat_engine,
            )
            tool_calls_made.append({
                "tool": tool_name,
                "args": tool_args,
                "result": tool_result,
            })

            # Feed tool result back to LLM for a summary
            followup_messages = messages + [
                {"role": "assistant", "content": reply},
                {
                    "role": "user",
                    "content": (
                        f"Tool '{tool_name}' executed. Result:\n"
                        f"{json.dumps(tool_result, indent=2, default=str)}\n\n"
                        "Please provide a clear summary of the result to the analyst."
                    ),
                },
            ]

            final_reply = await llm_router.complete_messages(
                followup_messages, max_tokens=900, temperature=0.2,
            )
            return {
                "response": final_reply,
                "provider": "openrouter",
                "tool_calls": tool_calls_made,
            }

        return {
            "response": reply,
            "provider": "openrouter",
            "tool_calls": [],
        }

    # ── Tool call parsing ────────────────────────────────────────────────

    def _parse_tool_call(self, text: str) -> dict | None:
        """Extract tool_call JSON from LLM response."""
        # Try to find JSON with tool_call key
        # First try: direct JSON parse
        try:
            data = json.loads(text.strip())
            if isinstance(data, dict) and "tool_call" in data:
                return data["tool_call"]
        except (json.JSONDecodeError, ValueError):
            pass

        # Second try: extract from markdown code block
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group(1))
                if isinstance(data, dict) and "tool_call" in data:
                    return data["tool_call"]
            except (json.JSONDecodeError, ValueError):
                pass

        # Third try: find any JSON block with tool_call
        m = re.search(r"\{[^{}]*\"tool_call\"[^{}]*\{[^}]*\}[^{}]*\}", text, re.DOTALL)
        if m:
            try:
                data = json.loads(m.group())
                if isinstance(data, dict) and "tool_call" in data:
                    return data["tool_call"]
            except (json.JSONDecodeError, ValueError):
                pass

        return None

    # ── Context building ─────────────────────────────────────────────────

    async def _build_context(self, threat_engine: Any) -> str:
        """Build a brief context string with current system state."""
        parts: list[str] = []

        if threat_engine:
            try:
                active = getattr(threat_engine, "active_threats", {})
                total = getattr(threat_engine, "total_threats_detected", 0)
                resolved = getattr(threat_engine, "total_threats_resolved", 0)
                active_count = len(active) if isinstance(active, dict) else 0
                parts.append(
                    f"Active threats: {active_count} | "
                    f"Total detected: {total} | "
                    f"Resolved: {resolved}"
                )
            except Exception:
                parts.append("Threat engine: status unavailable")

        return "\n".join(parts)

    # ── Tool execution ───────────────────────────────────────────────────

    async def _execute_tool(
        self,
        tool_name: str,
        args: dict,
        threat_engine: Any,
    ) -> dict:
        """Execute a security tool and return the result as a dict."""
        try:
            if tool_name == "run_scan":
                return await self._tool_run_scan(args)
            elif tool_name == "verify_pipeline":
                return await self._tool_verify_pipeline()
            elif tool_name == "get_threats":
                return await self._tool_get_threats(args, threat_engine)
            elif tool_name == "get_threat_stats":
                return await self._tool_get_threat_stats(threat_engine)
            elif tool_name == "resolve_threat":
                return await self._tool_resolve_threat(args, threat_engine)
            elif tool_name == "enrich_ip":
                return await self._tool_enrich_ip(args)
            elif tool_name == "get_system_health":
                return await self._tool_get_system_health()
            elif tool_name == "get_scan_tasks":
                return await self._tool_get_scan_tasks()
            elif tool_name == "get_kill_chain":
                return await self._tool_get_kill_chain()
            elif tool_name == "block_ip":
                return await self._tool_block_ip(args, threat_engine)
            elif tool_name == "run_nuclei_scan":
                return await self._tool_run_nuclei(args)
            else:
                return {"error": f"Unknown tool: {tool_name}"}
        except Exception as exc:
            logger.error("Tool %s failed: %s", tool_name, exc)
            return {"error": str(exc)}

    # ── Individual tool implementations ──────────────────────────────────

    async def _tool_run_scan(self, args: dict) -> dict:
        from modules.security_orchestrator import security_orchestrator
        desc = args.get("description", "AI-initiated security scan")
        task_id = await security_orchestrator.start_full_scan(description=desc)
        return {"task_id": task_id, "status": "started", "description": desc}

    async def _tool_verify_pipeline(self) -> dict:
        from modules.security_orchestrator import security_orchestrator
        result = await security_orchestrator.verify_pipeline(user_id="ai-agent")
        return result

    async def _tool_get_threats(self, args: dict, engine: Any) -> dict:
        if not engine:
            return {"error": "Threat engine unavailable"}
        status = args.get("status", "active")
        active = getattr(engine, "active_threats", {})
        if isinstance(active, dict):
            threats = list(active.values())[:20]
            return {
                "count": len(threats),
                "threats": [
                    {
                        "id": t.id,
                        "type": t.type,
                        "severity": t.severity,
                        "source": t.source,
                        "description": (t.description or "")[:120],
                        "status": t.status,
                    }
                    for t in threats
                ],
            }
        return {"count": 0, "threats": []}

    async def _tool_get_threat_stats(self, engine: Any) -> dict:
        if not engine:
            return {"error": "Threat engine unavailable"}
        active = getattr(engine, "active_threats", {})
        active_count = len(active) if isinstance(active, dict) else 0
        total = getattr(engine, "total_threats_detected", 0)
        resolved = getattr(engine, "total_threats_resolved", 0)
        return {
            "active_threats": active_count,
            "total_detected": total,
            "total_resolved": resolved,
        }

    async def _tool_resolve_threat(self, args: dict, engine: Any) -> dict:
        if not engine:
            return {"error": "Threat engine unavailable"}
        threat_id = args.get("id", "")
        note = args.get("note", "Resolved via AI assistant")
        if not threat_id:
            return {"error": "No threat ID provided"}
        result = await engine.resolve_threat(threat_id, note=note)
        return {"resolved": True, "threat_id": threat_id, "result": str(result)}

    async def _tool_enrich_ip(self, args: dict) -> dict:
        ip = args.get("ip", "")
        if not ip:
            return {"error": "No IP provided"}
        from modules.threat_intel import enrich_ip
        result = await enrich_ip(ip)
        return result

    async def _tool_get_system_health(self) -> dict:
        try:
            import psutil
            return {
                "cpu_percent": psutil.cpu_percent(interval=0.1),
                "memory_percent": psutil.virtual_memory().percent,
                "disk_percent": psutil.disk_usage("/").percent,
                "status": "healthy",
            }
        except Exception:
            return {"status": "health check unavailable"}

    async def _tool_get_scan_tasks(self) -> dict:
        try:
            from modules.security_orchestrator import security_orchestrator
            tasks = security_orchestrator.get_recent_tasks(limit=10)
            return {
                "count": len(tasks),
                "tasks": [
                    {
                        "id": t.get("id", ""),
                        "status": t.get("status", ""),
                        "description": t.get("description", ""),
                        "created_at": str(t.get("created_at", "")),
                    }
                    for t in tasks
                ],
            }
        except Exception as exc:
            return {"error": str(exc), "tasks": []}

    async def _tool_get_kill_chain(self) -> dict:
        try:
            from core.kill_chain_tracker import kill_chain_tracker
            status = kill_chain_tracker.get_status()
            return status
        except Exception:
            return {"status": "kill chain tracker unavailable"}

    async def _tool_block_ip(self, args: dict, engine: Any) -> dict:
        ip = args.get("ip", "")
        if not ip:
            return {"error": "No IP provided"}
        if engine:
            engine.register_threat(
                type="blocked_ip",
                severity="high",
                source=ip,
                description=f"IP blocked via AI assistant: {ip}",
                module="ai_agent",
            )
        return {"blocked": True, "ip": ip, "message": f"IP {ip} registered as blocked"}

    async def _tool_run_nuclei(self, args: dict) -> dict:
        from modules.security_orchestrator import security_orchestrator
        target = args.get("target", "localhost")
        desc = f"Nuclei vuln scan: {target}"
        task_id = await security_orchestrator.start_full_scan(
            description=desc,
            target_dirs=[target],
        )
        return {"task_id": task_id, "status": "started", "target": target}


# Application-wide singleton
soc_agent = SOCAgent()
