"""
THREAT INTELLIGENCE tool handlers.
Delegates to VirusTotal, Shodan, and MITRE ATT&CK via existing modules.
"""
from __future__ import annotations
import os
from typing import Any

_NA = "No real data available for {tool}"


async def lookup_ioc(ioc: str, ioc_type: str = "auto", **_: Any) -> dict:
    try:
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not vt_key:
            return {"status": "error", "message": "VIRUSTOTAL_API_KEY not configured"}
        import vt
        async with vt.Client(vt_key) as client:
            if ioc_type == "hash" or (len(ioc) in (32, 40, 64) and all(c in "0123456789abcdefABCDEF" for c in ioc)):
                obj = await client.get_object_async(f"/files/{ioc}")
            elif ioc_type == "ip" or _is_ip(ioc):
                obj = await client.get_object_async(f"/ip_addresses/{ioc}")
            else:
                obj = await client.get_object_async(f"/domains/{ioc}")
            return {"status": "ok", "ioc": ioc, "result": obj.to_dict()}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="lookup_ioc")}


async def check_ip_reputation(ip: str, **_: Any) -> dict:
    try:
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not vt_key:
            return {"status": "error", "message": "VIRUSTOTAL_API_KEY not configured"}
        import vt
        async with vt.Client(vt_key) as client:
            obj = await client.get_object_async(f"/ip_addresses/{ip}")
            stats = obj.last_analysis_stats if hasattr(obj, "last_analysis_stats") else {}
            return {"status": "ok", "ip": ip, "analysis_stats": stats}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="check_ip_reputation")}


async def check_domain_reputation(domain: str, **_: Any) -> dict:
    try:
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not vt_key:
            return {"status": "error", "message": "VIRUSTOTAL_API_KEY not configured"}
        import vt
        async with vt.Client(vt_key) as client:
            obj = await client.get_object_async(f"/domains/{domain}")
            stats = obj.last_analysis_stats if hasattr(obj, "last_analysis_stats") else {}
            return {"status": "ok", "domain": domain, "analysis_stats": stats}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="check_domain_reputation")}


async def check_hash_reputation(file_hash: str, **_: Any) -> dict:
    try:
        vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not vt_key:
            return {"status": "error", "message": "VIRUSTOTAL_API_KEY not configured"}
        import vt
        async with vt.Client(vt_key) as client:
            obj = await client.get_object_async(f"/files/{file_hash}")
            stats = obj.last_analysis_stats if hasattr(obj, "last_analysis_stats") else {}
            return {"status": "ok", "hash": file_hash, "analysis_stats": stats}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="check_hash_reputation")}


async def map_to_mitre_attack(techniques: list | None = None, **_: Any) -> dict:
    try:
        # Use pyattck if available
        from pyattck import Attck
        attack = Attck()
        if not techniques:
            # Return all technique names as context
            tech_list = [
                {"id": t.id, "name": t.name, "tactic": [ta.name for ta in t.tactics]}
                for t in attack.enterprise.techniques[:50]
            ]
        else:
            tech_list = []
            for tid in techniques:
                for t in attack.enterprise.techniques:
                    if t.id == tid or t.name.lower() == str(tid).lower():
                        tech_list.append({
                            "id": t.id, "name": t.name,
                            "description": t.description[:200] if t.description else "",
                            "tactic": [ta.name for ta in t.tactics],
                        })
                        break
        return {"status": "ok", "techniques": tech_list}
    except Exception as e:
        return {"status": "error", "error": str(e), "message": _NA.format(tool="map_to_mitre_attack")}


def _is_ip(value: str) -> bool:
    import re
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", value))
