"""AISS - Cyber Kill Chain API
Maps detected threats to MITRE/Lockheed Martin kill chain stages.
Uses networkx to build a directed threat graph (nodes=threats, edges=causal/campaign links).
"""

import asyncio
import time as _time
from fastapi import APIRouter, Depends
from core.dependencies import get_engine
from core.threat_engine import ThreatEngine

router = APIRouter()

# Simple in-process cache (10-second TTL) so the heavy graph build doesn't block
_kill_chain_cache: dict = {"data": None, "ts": 0.0}
_KILL_CHAIN_TTL = 30.0

# ── Stage mapping ─────────────────────────────────────────────────────
STAGE_MAP = {
    # Reconnaissance
    "Port Scan":               "Reconnaissance",
    "Network Intrusion":       "Reconnaissance",

    # Initial Access
    "Brute Force Attack":      "Initial Access",
    "Credential Stuffing":     "Initial Access",
    "Phishing Attempt":        "Initial Access",
    "Command & Control Traffic": "Initial Access",
    "DNS Hijacking":           "Initial Access",
    "Man-in-the-Middle":       "Initial Access",
    "ARP Spoofing":            "Initial Access",

    # Execution
    "Malicious Script":        "Execution",
    "Fileless Malware":        "Execution",
    "Trojan":                  "Execution",
    "Virus":                   "Execution",
    "Worm":                    "Execution",

    # Privilege Escalation
    "Privilege Escalation":    "Privilege Escalation",
    "Rootkit":                 "Privilege Escalation",

    # Defense Evasion
    "Suspicious File":         "Defense Evasion",
    "Adware":                  "Defense Evasion",
    "Spyware":                 "Defense Evasion",
    "Keylogger":               "Defense Evasion",

    # Lateral Movement
    "Botnet":                  "Lateral Movement",
    "DDoS Attack":             "Lateral Movement",

    # Command & Control
    "Cryptominer":             "Command & Control",

    # Exfiltration
    "Data Exfiltration":       "Exfiltration",
    "Ransomware":              "Exfiltration",
}

STAGES = [
    {
        "id":          "reconnaissance",
        "label":       "Reconnaissance",
        "description": "Attacker gathers information about the target",
        "icon":        "🔍",
        "color":       "#6366f1",
    },
    {
        "id":          "initial_access",
        "label":       "Initial Access",
        "description": "Attacker gains entry into the network",
        "icon":        "🚪",
        "color":       "#f59e0b",
    },
    {
        "id":          "execution",
        "label":       "Execution",
        "description": "Malicious code is run on the system",
        "icon":        "⚡",
        "color":       "#ef4444",
    },
    {
        "id":          "privilege_escalation",
        "label":       "Privilege Escalation",
        "description": "Attacker gains elevated permissions",
        "icon":        "🔓",
        "color":       "#dc2626",
    },
    {
        "id":          "defense_evasion",
        "label":       "Defense Evasion",
        "description": "Attacker hides presence from defenses",
        "icon":        "🥷",
        "color":       "#7c3aed",
    },
    {
        "id":          "lateral_movement",
        "label":       "Lateral Movement",
        "description": "Attacker moves across the network",
        "icon":        "↔️",
        "color":       "#0891b2",
    },
    {
        "id":          "command_control",
        "label":       "Command & Control",
        "description": "Attacker maintains remote control",
        "icon":        "📡",
        "color":       "#059669",
    },
    {
        "id":          "exfiltration",
        "label":       "Exfiltration",
        "description": "Data is stolen or destroyed",
        "icon":        "💀",
        "color":       "#ff0000",
    },
]

LABEL_TO_ID = {s["label"]: s["id"] for s in STAGES}


@router.get("/kill-chain")
async def get_kill_chain(engine: ThreatEngine = Depends(get_engine)):
    """
    Returns all threats grouped by kill chain stage.
    Entire computation runs in a thread-pool executor to avoid blocking
    the async event loop during concurrent threat scans.
    Cached for 30 seconds.
    """
    global _kill_chain_cache
    now = _time.monotonic()
    if _kill_chain_cache["data"] is not None and (now - _kill_chain_cache["ts"]) < _KILL_CHAIN_TTL:
        return _kill_chain_cache["data"]

    def _compute() -> dict:
        all_threats = engine.get_all_threats()

        # Limit to most recent 200 threats
        if len(all_threats) > 200:
            all_threats = sorted(
                all_threats,
                key=lambda t: t.get("detected_at", ""),
                reverse=True,
            )[:200]

        # Group by stage
        stage_threats: dict[str, list] = {s["id"]: [] for s in STAGES}
        for threat in all_threats:
            stage_label = STAGE_MAP.get(threat.get("type", ""), "")
            stage_id    = LABEL_TO_ID.get(stage_label, "")
            if stage_id:
                stage_threats[stage_id].append(threat)

        result = []
        for stage in STAGES:
            sid     = stage["id"]
            threats = stage_threats[sid]
            result.append({
                **stage,
                "threats":     threats[:10],  # cap per-stage list for JSON size
                "total":       len(threats),
                "active":      sum(1 for t in threats if t.get("status") == "active"),
                "critical":    sum(1 for t in threats if t.get("severity") == "critical"),
                "compromised": len(threats) > 0,
            })

        total_compromised = sum(1 for s in result if s["compromised"])
        graph = _build_threat_graph(all_threats, result)

        return {
            "stages":             result,
            "total_threats":      len(all_threats),
            "stages_compromised": total_compromised,
            "attack_progress":    round((total_compromised / len(STAGES)) * 100),
            "graph":              graph,
        }

    loop = asyncio.get_event_loop()
    response = await loop.run_in_executor(None, _compute)
    _kill_chain_cache["data"] = response
    _kill_chain_cache["ts"]   = _time.monotonic()
    return response


def _build_threat_graph(all_threats: list, stages: list) -> dict:
    """
    Build a directed threat graph using networkx.
    Nodes: stage nodes + top 50 threats per severity
    Edges: threat → stage (belongs_to) only (temporal edges skipped for performance)
    """
    try:
        import networkx as nx

        G = nx.DiGraph()

        # ── Stage nodes ───────────────────────────────────────────────
        for stage in stages:
            G.add_node(
                f"stage:{stage['id']}",
                label=stage["label"],
                type="stage",
                color=stage["color"],
                compromised=stage["compromised"],
            )

        # ── Limit threat nodes to 50 most recent to keep graph fast ──
        sample = sorted(all_threats, key=lambda t: t.get("detected_at", ""), reverse=True)[:50]

        for t in sample:
            tid = t.get("id", "")
            G.add_node(
                tid,
                label=t.get("type", ""),
                severity=t.get("severity", ""),
                source=t.get("source", ""),
                status=t.get("status", ""),
                type="threat",
            )
            # Edge: threat → stage
            stage_label = STAGE_MAP.get(t.get("type", ""), "")
            stage_id    = LABEL_TO_ID.get(stage_label, "")
            if stage_id:
                G.add_edge(tid, f"stage:{stage_id}", relation="belongs_to")

        # ── Serialize ─────────────────────────────────────────────────
        nodes = [{"id": n, **G.nodes[n]} for n in G.nodes()]
        edges = [
            {"source": u, "target": v, "relation": G.edges[u, v].get("relation", "")}
            for u, v in G.edges()
        ]
        return {"nodes": nodes, "edges": edges, "node_count": len(nodes), "edge_count": len(edges)}

    except Exception as e:
        return {"nodes": [], "edges": [], "error": str(e), "node_count": 0, "edge_count": 0}
