"""AISS — Remote Agent System
Allows multiple computers to connect to AISS as monitored agents.

Architecture:
  ┌─────────────────────────────────────────────────────────┐
  │  AISS Server (this machine)                             │
  │  ┌──────────────┐   WebSocket    ┌──────────────────┐  │
  │  │ AgentManager │ ◄──────────── │ Remote Agent     │  │
  │  │  /api/agents │               │ (another PC)     │  │
  │  └──────────────┘               │ runs agent.py    │  │
  └─────────────────────────────────┴──────────────────────┘

Supports: LAN (192.168.x.x), WAN (public IP), MAN (VPN/tunnel)

Agent capabilities on remote machines:
  - Process monitoring (psutil)
  - Network connection monitoring
  - File system monitoring
  - CPU/RAM/disk metrics
  - Threat events forwarded to AISS server

Usage on remote machine:
    python aiss_agent.py --server wss://your-aiss-server:8000 --token YOUR_TOKEN

API endpoints:
    GET  /api/agents/              — list all connected agents
    GET  /api/agents/{id}          — agent details + live metrics
    POST /api/agents/token/generate — generate agent auth token
    GET  /api/agents/{id}/threats  — threats from this agent
    POST /api/agents/{id}/command  — send command to agent
    WS   /ws/agent                 — agent WebSocket connection
"""
import asyncio
import hashlib
import json
import os
import platform
import secrets
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import WebSocket, WebSocketDisconnect
from utils.logger import setup_logger

logger = setup_logger("remote_agent")

# ─────────────────────────────────────────────────────────────────────
# Agent data model
# ─────────────────────────────────────────────────────────────────────

@dataclass
class AgentInfo:
    id:           str
    hostname:     str
    ip:           str
    os_name:      str
    os_version:   str
    python_ver:   str
    aiss_ver:     str
    connected_at: str
    last_seen:    str
    status:       str  = "connected"   # connected | disconnected | idle
    # Live metrics (updated every 5s by agent heartbeat)
    cpu_percent:   float = 0.0
    ram_percent:   float = 0.0
    ram_used_mb:   int   = 0
    disk_percent:  float = 0.0
    process_count: int   = 0
    threat_count:  int   = 0
    # Network info
    local_ips:     list  = field(default_factory=list)
    network_type:  str   = "unknown"   # lan | wan | vpn | man
    # Capabilities
    capabilities:  list  = field(default_factory=list)
    tags:          list  = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────
# Token store  (simple in-memory; persist in DB for production)
# ─────────────────────────────────────────────────────────────────────

_agent_tokens:  dict[str, dict] = {}   # token_hash → {label, created_at, last_used}
_agent_registry: dict[str, AgentInfo] = {}
_agent_sockets:  dict[str, WebSocket] = {}
_agent_threats:  dict[str, list] = defaultdict(list)


def generate_agent_token(label: str = "agent") -> dict:
    """Generate a new agent authentication token."""
    raw   = secrets.token_hex(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    _agent_tokens[hashed] = {
        "label":      label,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_used":  None,
    }
    return {"token": raw, "label": label,
            "note": "Pass this token to the agent with --token flag"}


def validate_agent_token(raw_token: str) -> bool:
    hashed = hashlib.sha256(raw_token.encode()).hexdigest()
    if hashed in _agent_tokens:
        _agent_tokens[hashed]["last_used"] = datetime.now(timezone.utc).isoformat()
        return True
    return False


def _classify_network(ip: str) -> str:
    """Classify connection type from IP."""
    if not ip:
        return "unknown"
    parts = ip.split(".")
    if len(parts) != 4:
        return "wan"
    try:
        a, b = int(parts[0]), int(parts[1])
        if a == 10:                       return "lan"
        if a == 172 and 16 <= b <= 31:    return "lan"
        if a == 192 and b == 168:         return "lan"
        if a == 100 and 64 <= b <= 127:   return "man"  # carrier-grade NAT
        if ip.startswith("10.8."):        return "vpn"
    except Exception:
        pass
    return "wan"


# ─────────────────────────────────────────────────────────────────────
# AgentManager
# ─────────────────────────────────────────────────────────────────────

class AgentManager:
    """Manages all connected remote agents."""

    # ── WebSocket handler (called from /ws/agent endpoint) ───────────
    async def handle_connection(self, ws: WebSocket) -> None:
        await ws.accept()
        agent_id = None

        try:
            # Step 1: Auth handshake
            raw = await asyncio.wait_for(ws.receive_text(), timeout=15.0)
            msg = json.loads(raw)

            if msg.get("action") != "auth" or not msg.get("token"):
                await ws.send_text(json.dumps({"error": "Send {action:'auth', token:'...'}" }))
                await ws.close(code=1008)
                return

            if not validate_agent_token(msg["token"]):
                await ws.send_text(json.dumps({"error": "Invalid agent token"}))
                await ws.close(code=1008)
                logger.warning(f"Agent auth failed from {ws.client.host if ws.client else '?'}")
                return

            # Step 2: Register agent
            info_raw = msg.get("info", {})
            client_ip = ws.client.host if ws.client else "unknown"
            agent_id  = info_raw.get("id") or str(uuid.uuid4())

            agent = AgentInfo(
                id           = agent_id,
                hostname     = info_raw.get("hostname", "unknown"),
                ip           = client_ip,
                os_name      = info_raw.get("os_name", "unknown"),
                os_version   = info_raw.get("os_version", ""),
                python_ver   = info_raw.get("python_ver", ""),
                aiss_ver     = info_raw.get("aiss_ver", ""),
                connected_at = datetime.now(timezone.utc).isoformat(),
                last_seen    = datetime.now(timezone.utc).isoformat(),
                local_ips    = info_raw.get("local_ips", []),
                network_type = _classify_network(client_ip),
                capabilities = info_raw.get("capabilities", []),
                tags         = info_raw.get("tags", []),
            )
            _agent_registry[agent_id] = agent
            _agent_sockets[agent_id]  = ws

            await ws.send_text(json.dumps({
                "status":   "authenticated",
                "agent_id": agent_id,
                "message":  f"Connected to AISS server. Agent ID: {agent_id}",
            }))
            logger.info(f"Agent connected: {agent.hostname} ({client_ip}) "
                        f"[{agent.network_type}] id={agent_id[:8]}")

            # Step 3: Message loop
            while True:
                raw  = await asyncio.wait_for(ws.receive_text(), timeout=60.0)
                data = json.loads(raw)
                await self._handle_message(agent_id, data)

        except asyncio.TimeoutError:
            if agent_id:
                logger.info(f"Agent timeout: {agent_id[:8]}")
        except WebSocketDisconnect:
            pass
        except Exception as e:
            logger.debug(f"Agent WS error: {e}")
        finally:
            if agent_id and agent_id in _agent_registry:
                _agent_registry[agent_id].status = "disconnected"
                _agent_sockets.pop(agent_id, None)
                logger.info(f"Agent disconnected: {agent_id[:8]}")

    async def _handle_message(self, agent_id: str, data: dict) -> None:
        action = data.get("action", "")
        agent  = _agent_registry.get(agent_id)
        if not agent:
            return

        agent.last_seen = datetime.now(timezone.utc).isoformat()

        if action == "heartbeat":
            # Update live metrics
            m = data.get("metrics", {})
            agent.cpu_percent   = m.get("cpu_percent",   agent.cpu_percent)
            agent.ram_percent   = m.get("ram_percent",   agent.ram_percent)
            agent.ram_used_mb   = m.get("ram_used_mb",   agent.ram_used_mb)
            agent.disk_percent  = m.get("disk_percent",  agent.disk_percent)
            agent.process_count = m.get("process_count", agent.process_count)
            agent.status        = "connected"

        elif action == "threat":
            # Agent detected a threat — forward to AISS engine
            threat_data = data.get("threat", {})
            threat_data["agent_id"]   = agent_id
            threat_data["agent_host"] = agent.hostname
            threat_data["source"]     = f"agent:{agent.hostname}:{agent.ip}"
            _agent_threats[agent_id].append(threat_data)
            agent.threat_count += 1

            # Forward to central ThreatEngine
            try:
                from core.dependencies import get_engine
                engine = get_engine()
                from models.threat import Threat, ThreatType, ThreatSeverity
                t = Threat(
                    type        = ThreatType(threat_data.get("type", "intrusion")),
                    description = f"[Agent:{agent.hostname}] {threat_data.get('description','')}",
                    severity    = ThreatSeverity(threat_data.get("severity", "medium")),
                    source      = threat_data["source"],
                    module      = f"remote_agent:{agent.hostname}",
                    metadata    = threat_data,
                )
                asyncio.create_task(engine.register_threat(t))
            except Exception as e:
                logger.debug(f"Could not forward agent threat to engine: {e}")

        elif action == "metrics_update":
            # Bulk metrics update
            pass

    # ── Management API ─────────────────────────────────────────────────

    def get_all_agents(self) -> list[dict]:
        return [a.to_dict() for a in _agent_registry.values()]

    def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        return _agent_registry.get(agent_id)

    def get_agent_threats(self, agent_id: str, limit: int = 100) -> list:
        return _agent_threats.get(agent_id, [])[-limit:]

    async def send_command(self, agent_id: str, command: str, params: dict = None) -> bool:
        """Send a command to a connected agent."""
        ws = _agent_sockets.get(agent_id)
        if not ws:
            return False
        try:
            await ws.send_text(json.dumps({
                "action":  "command",
                "command": command,
                "params":  params or {},
            }))
            return True
        except Exception as e:
            logger.warning(f"Failed to send command to agent {agent_id[:8]}: {e}")
            return False

    def get_stats(self) -> dict:
        agents = list(_agent_registry.values())
        return {
            "total":       len(agents),
            "connected":   sum(1 for a in agents if a.status == "connected"),
            "disconnected":sum(1 for a in agents if a.status == "disconnected"),
            "by_network":  {
                "lan": sum(1 for a in agents if a.network_type == "lan"),
                "wan": sum(1 for a in agents if a.network_type == "wan"),
                "vpn": sum(1 for a in agents if a.network_type == "vpn"),
                "man": sum(1 for a in agents if a.network_type == "man"),
            },
            "total_threats": sum(a.threat_count for a in agents),
        }

    def list_tokens(self) -> list[dict]:
        return [
            {"hash_prefix": k[:8] + "...", **v}
            for k, v in _agent_tokens.items()
        ]

    def revoke_token(self, label: str) -> int:
        """Revoke all tokens with the given label. Returns count removed."""
        before = len(_agent_tokens)
        to_del = [k for k, v in _agent_tokens.items() if v["label"] == label]
        for k in to_del:
            del _agent_tokens[k]
        return before - len(_agent_tokens)


# Singleton
agent_manager = AgentManager()
