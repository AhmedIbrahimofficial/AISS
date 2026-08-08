"""AISS - Cyber Kill Chain API
Maps detected threats to MITRE/Lockheed Martin kill chain stages.
Uses networkx to build a directed threat graph (nodes=threats, edges=causal/campaign links).
"""

from fastapi import APIRouter, Depends
from core.dependencies import get_engine
from core.threat_engine import ThreatEngine

router = APIRouter()

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
    Returns all threats grouped by kill chain stage,
    plus a networkx-derived node/edge graph for the frontend.
    """
    all_threats = engine.get_all_threats()

    # Group threats by stage
    stage_threats: dict[str, list] = {s["id"]: [] for s in STAGES}

    for threat in all_threats:
        threat_type  = threat.get("type", "")
        stage_label  = STAGE_MAP.get(threat_type, "")
        stage_id     = LABEL_TO_ID.get(stage_label, "")
        if stage_id:
            stage_threats[stage_id].append(threat)

    # Build response
    result = []
    for stage in STAGES:
        sid      = stage["id"]
        threats  = stage_threats[sid]
        active   = sum(1 for t in threats if t.get("status") == "active")
        critical = sum(1 for t in threats if t.get("severity") == "critical")

        result.append({
            **stage,
            "threats":     threats,
            "total":       len(threats),
            "active":      active,
            "critical":    critical,
            "compromised": len(threats) > 0,
        })

    total_compromised = sum(1 for s in result if s["compromised"])

    # ── NetworkX threat graph ─────────────────────────────────────────
    graph = _build_threat_graph(all_threats, result)

    return {
        "stages":             result,
        "total_threats":      len(all_threats),
        "stages_compromised": total_compromised,
        "attack_progress":    round((total_compromised / len(STAGES)) * 100),
        "graph":              graph,
    }


def _build_threat_graph(all_threats: list, stages: list) -> dict:
    """
    Build a directed threat graph using networkx.

    Nodes: threats + stage nodes
    Edges:
      - threat → stage (belongs_to)
      - campaign.linked_threats → causal links
      - same source IP threats → temporal edges
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

        # ── Threat nodes ──────────────────────────────────────────────
        for t in all_threats:
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
            threat_type = t.get("type", "")
            stage_label = STAGE_MAP.get(threat_type, "")
            stage_id    = LABEL_TO_ID.get(stage_label, "")
            if stage_id:
                G.add_edge(tid, f"stage:{stage_id}", relation="belongs_to")

        # ── Campaign causal links ─────────────────────────────────────
        for t in all_threats:
            meta = t.get("metadata") or {}
            if meta.get("campaign"):
                linked = meta.get("linked_threats", [])
                for ltid in linked:
                    if G.has_node(ltid) and G.has_node(t.get("id", "")):
                        G.add_edge(ltid, t.get("id", ""), relation="campaign_link")

        # ── Same-source temporal links ────────────────────────────────
        from collections import defaultdict
        by_source: dict[str, list] = defaultdict(list)
        for t in all_threats:
            src = t.get("source", "")
            if src and not src.startswith("PID:"):
                by_source[src].append(t)

        for src, threats in by_source.items():
            if len(threats) > 1:
                # Sort by detected_at, add temporal edges
                sorted_threats = sorted(threats, key=lambda x: x.get("detected_at", ""))
                for i in range(len(sorted_threats) - 1):
                    a = sorted_threats[i].get("id", "")
                    b = sorted_threats[i+1].get("id", "")
                    if G.has_node(a) and G.has_node(b) and not G.has_edge(a, b):
                        G.add_edge(a, b, relation="temporal_sequence")

        # ── Serialize to JSON-safe format ─────────────────────────────
        nodes = [
            {"id": n, **G.nodes[n]}
            for n in G.nodes()
        ]
        edges = [
            {"source": u, "target": v, "relation": G.edges[u, v].get("relation", "")}
            for u, v in G.edges()
        ]

        return {
            "nodes":      nodes,
            "edges":      edges,
            "node_count": len(nodes),
            "edge_count": len(edges),
        }

    except Exception as e:
        return {"nodes": [], "edges": [], "error": str(e)}
