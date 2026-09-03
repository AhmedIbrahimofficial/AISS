"""AISS - Autonomous Security Orchestrator

Drives the full security operations lifecycle:
  local discovery → network discovery → file/malware scan → indicator extraction
  → threat intel enrichment → vulnerability checks → correlation
  → finding creation → recommended response.

Every result comes from real tool execution or real telemetry.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import platform
import re
import tempfile
import time
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from agents.models import AgentExecution, AgentTask, SecurityFinding, ToolExecution
from core.database import AsyncSessionLocal
from core.websocket_manager import WebSocketManager
from models.threat import Threat, ThreatSeverity, ThreatType
from utils.logger import setup_logger

from modules.clamav_scanner import scan_paths as clamav_scan_paths
from modules.ioc_extractor import ioc_extractor
from modules.local_discovery import discover_local_asset, get_default_scan_directories, get_local_subnets
from modules.threat_intel import enrich_ip, vt_check_hash, vt_check_domain, vt_check_url
from modules.vuln_scanner import run_vulnerability_scan
from modules.yara_scanner import scan_file as yara_scan_file

logger = setup_logger("security_orchestrator")

IS_WINDOWS = platform.system() == "Windows"

# EICAR test file content (standard antivirus test string)
EICAR_CONTENT = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
EICAR_SHA256 = hashlib.sha256(EICAR_CONTENT).hexdigest()


class ScanPhase:
    PENDING = "pending"
    LOCAL_DISCOVERY = "local_discovery"
    NETWORK_DISCOVERY = "network_discovery"
    FILE_SCAN = "file_scan"
    EICAR_VERIFICATION = "eicar_verification"
    IOC_ENRICHMENT = "ioc_enrichment"
    VULNERABILITY_CHECK = "vulnerability_check"
    CORRELATION = "correlation"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SecurityOrchestrator:
    """Coordinates autonomous security scans and produces evidence-backed findings."""

    def __init__(self, ws_manager: Optional[WebSocketManager] = None):
        self.ws_manager = ws_manager
        self._running: dict[str, asyncio.Task] = {}

    async def _broadcast(self, message: dict) -> None:
        if self.ws_manager:
            try:
                await self.ws_manager.broadcast(message)
            except Exception as e:
                logger.debug(f"WebSocket broadcast failed: {e}")

    async def _update_progress(
        self,
        task_id: str,
        phase: str,
        percent: int,
        message: str,
        details: Optional[dict] = None,
    ) -> None:
        payload = {
            "event": "scan_progress",
            "task_id": task_id,
            "phase": phase,
            "percent": percent,
            "message": message,
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {},
        }
        await self._broadcast(payload)
        logger.info(f"[Scan {task_id}] {phase} ({percent}%): {message}")

    async def start_full_scan(
        self,
        user_id: str,
        description: str = "Autonomous Full Security Scan",
        eicar_test: bool = False,
        target_dirs: Optional[list[str]] = None,
    ) -> str:
        """Start a full autonomous security scan and return the task id."""
        task_id = self._create_task_id()
        db = AsyncSessionLocal()
        try:
            task = AgentTask(
                id=task_id,
                user_id=user_id,
                status="running",
                description=description,
                plan_json={
                    "phases": [
                        ScanPhase.LOCAL_DISCOVERY,
                        ScanPhase.NETWORK_DISCOVERY,
                        ScanPhase.FILE_SCAN,
                        ScanPhase.IOC_ENRICHMENT,
                        ScanPhase.VULNERABILITY_CHECK,
                        ScanPhase.CORRELATION,
                    ],
                    "eicar_test": eicar_test,
                    "target_dirs": target_dirs,
                },
            )
            db.add(task)
            execution = AgentExecution(task_id=task_id, status="running")
            db.add(execution)
            await db.commit()
        finally:
            await db.close()

        coro = self._run_full_scan(task_id, user_id, eicar_test, target_dirs)
        task_obj = asyncio.create_task(coro)
        self._running[task_id] = task_obj
        task_obj.add_done_callback(lambda t: self._running.pop(task_id, None))
        return task_id

    def _create_task_id(self) -> str:
        import uuid
        return str(uuid.uuid4())

    async def _run_full_scan(
        self,
        task_id: str,
        user_id: str,
        eicar_test: bool,
        target_dirs: Optional[list[str]],
    ) -> None:
        """Execute all scan phases and persist findings."""
        try:
            await self._update_progress(task_id, ScanPhase.LOCAL_DISCOVERY, 5, "Discovering local asset information")
            try:
                local_asset = await asyncio.wait_for(discover_local_asset(), timeout=45.0)
            except asyncio.TimeoutError:
                local_asset = {"hostname": platform.node(), "os": platform.system(), "error": "local discovery timed out"}
                logger.warning(f"Scan {task_id}: local discovery exceeded 45s timeout")
                await self._record_finding(
                    task_id,
                    "scan_note",
                    "low",
                    "Local discovery timed out; continuing with limited asset information",
                    affected_resource=platform.node(),
                    recommendation="Consider running with higher privileges or reducing system load.",
                )
            await self._record_finding(
                task_id,
                "local_asset",
                "info",
                f"Local asset discovered: {local_asset.get('hostname')} ({local_asset.get('os')})",
                affected_resource=local_asset.get("hostname"),
                recommendation="Review asset inventory for unauthorized changes.",
            )

            # Optionally plant EICAR test artifact in a temp directory
            eicar_path: Optional[str] = None
            if eicar_test:
                eicar_dir = tempfile.mkdtemp(prefix="aiss_eicar_test_")
                eicar_path = os.path.join(eicar_dir, "eicar_test.txt")
                with open(eicar_path, "wb") as f:
                    f.write(EICAR_CONTENT)
                logger.info(f"EICAR test artifact planted at {eicar_path}")

            await self._update_progress(task_id, ScanPhase.NETWORK_DISCOVERY, 20, "Discovering local network hosts")
            try:
                network_results = await asyncio.wait_for(self._run_network_discovery(), timeout=90.0)
            except asyncio.TimeoutError:
                network_results = {"subnets": [], "hosts": [], "errors": ["network discovery timed out"]}
                logger.warning(f"Scan {task_id}: network discovery exceeded 90s timeout")
                await self._record_finding(
                    task_id,
                    "scan_note",
                    "low",
                    "Network discovery timed out; continuing with limited network information",
                    affected_resource=platform.node(),
                    recommendation="Verify network permissions and reduce scan scope.",
                )

            await self._update_progress(task_id, ScanPhase.FILE_SCAN, 40, "Scanning files for malware")
            scan_dirs = list(target_dirs) if target_dirs else get_default_scan_directories()
            if eicar_path:
                scan_dirs.insert(0, os.path.dirname(eicar_path))
            # For EICAR mode, keep scan tightly scoped to avoid long runtime
            if eicar_test and not target_dirs:
                scan_dirs = [os.path.dirname(eicar_path)]
            file_results = await asyncio.wait_for(self._scan_files(scan_dirs), timeout=120.0)

            # EICAR verification: explicitly check if the test artifact was detected
            eicar_verified = False
            if eicar_test and eicar_path:
                await self._update_progress(task_id, ScanPhase.EICAR_VERIFICATION, 55, "Verifying EICAR detection")
                eicar_verified = await self._verify_eicar_detection(task_id, file_results, eicar_path)

            await self._update_progress(task_id, ScanPhase.IOC_ENRICHMENT, 65, "Extracting and enriching indicators")
            enriched = await self._enrich_findings(file_results, network_results)

            await self._update_progress(task_id, ScanPhase.VULNERABILITY_CHECK, 80, "Checking for vulnerabilities")
            vuln_results = await self._check_vulnerabilities(local_asset, network_results)

            await self._update_progress(task_id, ScanPhase.CORRELATION, 90, "Correlating findings and creating incidents")
            await self._correlate_and_create_incidents(task_id, file_results, network_results, enriched, vuln_results)

            await self._mark_task_complete(task_id, "completed", eicar_verified=eicar_verified if eicar_test else None)
            await self._update_progress(task_id, ScanPhase.COMPLETED, 100, "Full security scan completed")

        except asyncio.CancelledError:
            await self._mark_task_complete(task_id, "cancelled")
            await self._update_progress(task_id, ScanPhase.CANCELLED, 0, "Scan cancelled by user")
        except Exception as e:
            logger.exception(f"Full scan {task_id} failed: {e}")
            await self._mark_task_complete(task_id, "failed", error=str(e))
            await self._update_progress(task_id, ScanPhase.FAILED, 0, f"Scan failed: {e}")

    async def _verify_eicar_detection(
        self,
        task_id: str,
        file_results: dict,
        eicar_path: str,
    ) -> bool:
        """Verify that the EICAR test artifact was detected by YARA or ClamAV.

        Returns True if detection pipeline correctly identified the EICAR file.
        """
        eicar_dir = os.path.dirname(eicar_path)
        eicar_detected = False
        detection_method: Optional[str] = None

        # Check YARA detections for EICAR path or signature
        for det in file_results.get("yara", {}).get("detections", []):
            det_path = det.get("path", "")
            if eicar_path in det_path or eicar_dir in det_path:
                eicar_detected = True
                detection_method = f"YARA rule '{det.get('rule', 'unknown')}'"
                break

        # Check ClamAV detections for EICAR
        if not eicar_detected:
            for det in file_results.get("clamav", {}).get("detections", []):
                det_path = det.get("path", "")
                malware_name = det.get("malware_name", "").lower()
                if (eicar_path in det_path or eicar_dir in det_path
                        or "eicar" in malware_name or "test file" in malware_name):
                    eicar_detected = True
                    detection_method = f"ClamAV ({det.get('malware_name', 'EICAR-Test-File')})"
                    break

        # Check file hashes for EICAR SHA256 match
        if not eicar_detected:
            for h in file_results.get("hashes", []):
                if h.get("sha256", "").lower() == EICAR_SHA256.lower():
                    eicar_detected = True
                    detection_method = f"SHA256 hash match ({EICAR_SHA256[:16]}...)"
                    break

        # Record verification finding
        if eicar_detected:
            await self._record_finding(
                task_id,
                "eicar_verification",
                "info",
                f"EICAR test PASSED: detection pipeline verified via {detection_method}",
                description=(
                    f"The EICAR standard antivirus test file was successfully detected "
                    f"by {detection_method}. The malware detection pipeline is functioning correctly."
                ),
                affected_resource=eicar_path,
                recommendation="Detection pipeline is operational. No action required.",
            )
            logger.info(f"[Scan {task_id}] EICAR verification PASSED via {detection_method}")
        else:
            await self._record_finding(
                task_id,
                "eicar_verification",
                "high",
                "EICAR test FAILED: EICAR artifact was not detected",
                description=(
                    "The EICAR standard antivirus test file was planted but NOT detected by any scanner. "
                    "This indicates a potential issue with the malware detection pipeline. "
                    "Verify that YARA rules or ClamAV signatures are properly loaded."
                ),
                affected_resource=eicar_path,
                recommendation=(
                    "Check YARA/ClamAV installation and signature updates. "
                    "Ensure scanning permissions are correct for the temp directory."
                ),
            )
            logger.warning(f"[Scan {task_id}] EICAR verification FAILED — detection pipeline issue")

        # Clean up the EICAR test file
        try:
            if os.path.exists(eicar_path):
                os.remove(eicar_path)
            if os.path.isdir(eicar_dir):
                os.rmdir(eicar_dir)
        except Exception as e:
            logger.debug(f"EICAR cleanup failed: {e}")

        return eicar_detected

    async def verify_pipeline(self, user_id: str) -> dict:
        """Run a lightweight EICAR-only verification and return results synchronously.

        Plants EICAR, scans the temp directory, verifies detection, and cleans up.
        Returns the verification result without running a full scan.
        """
        import uuid
        task_id = str(uuid.uuid4())

        # Plant EICAR
        eicar_dir = tempfile.mkdtemp(prefix="aiss_eicar_verify_")
        eicar_path = os.path.join(eicar_dir, "eicar_test.txt")
        with open(eicar_path, "wb") as f:
            f.write(EICAR_CONTENT)

        try:
            # Create task record
            db = AsyncSessionLocal()
            try:
                task = AgentTask(
                    id=task_id,
                    user_id=user_id,
                    status="running",
                    description="Pipeline verification (EICAR)",
                    plan_json={"phases": ["eicar_verification"], "eicar_test": True},
                )
                db.add(task)
                await db.commit()
            finally:
                await db.close()

            # Scan only the EICAR directory
            file_results = await asyncio.wait_for(
                self._scan_files([eicar_dir]),
                timeout=60.0,
            )

            # Verify detection
            eicar_verified = await self._verify_eicar_detection(task_id, file_results, eicar_path)

            # Mark task complete
            await self._mark_task_complete(task_id, "completed", eicar_verified=eicar_verified)

            # Get full task status
            status = await self.get_task_status(task_id)
            return {
                "verified": eicar_verified,
                "task_id": task_id,
                "eicar_sha256": EICAR_SHA256,
                "scanners_available": {
                    "yara": len(file_results.get("yara", {}).get("errors", [])) == 0,
                    "clamav": file_results.get("clamav", {}).get("installed", False),
                },
                "findings": status.get("findings", []) if status else [],
            }

        except asyncio.TimeoutError:
            await self._mark_task_complete(task_id, "failed", error="Verification timed out")
            return {"verified": False, "task_id": task_id, "error": "Verification timed out after 60s"}
        except Exception as e:
            await self._mark_task_complete(task_id, "failed", error=str(e))
            return {"verified": False, "task_id": task_id, "error": str(e)}
        finally:
            # Cleanup
            try:
                if os.path.exists(eicar_path):
                    os.remove(eicar_path)
                if os.path.isdir(eicar_dir):
                    os.rmdir(eicar_dir)
            except Exception:
                pass

    async def _run_network_discovery(self) -> dict:
        """Run automatic network discovery on local subnets."""
        results: dict = {"subnets": [], "hosts": [], "errors": []}
        try:
            subnets = get_local_subnets()
            results["subnets"] = subnets
            if not subnets:
                results["errors"].append("No local subnets detected")
                return results

            from modules.network_discovery.discovery_service import DiscoveryService
            service = DiscoveryService()
            for subnet in subnets[:3]:  # Limit scope to first 3 subnets
                try:
                    discovery = await asyncio.wait_for(
                        service.discover_hosts(subnet, method="arp"),
                        timeout=60.0,
                    )
                    if discovery and discovery.hosts:
                        results["hosts"].extend([h.model_dump() for h in discovery.hosts])
                    if discovery and discovery.errors:
                        results["errors"].extend(discovery.errors)
                except asyncio.TimeoutError:
                    results["errors"].append(f"Host discovery timeout for {subnet}")
                except Exception as e:
                    results["errors"].append(f"Host discovery failed for {subnet}: {e}")
        except Exception as e:
            results["errors"].append(f"Network discovery error: {e}")
        return results

    async def _scan_files(self, directories: list[str]) -> dict:
        """Scan target directories with YARA and ClamAV."""
        results: dict = {
            "scanned_dirs": directories,
            "clamav": {"installed": False, "detections": [], "errors": []},
            "yara": {"detections": [], "errors": []},
            "hashes": [],
        }

        # Collect candidate files (limit to avoid excessive runtime)
        candidate_files: list[str] = []
        for d in directories:
            if not os.path.isdir(d):
                continue
            try:
                for root, _, files in os.walk(d):
                    for fname in files:
                        path = os.path.join(root, fname)
                        candidate_files.append(path)
                        if len(candidate_files) >= 500:
                            break
                    if len(candidate_files) >= 500:
                        break
            except Exception as e:
                results["yara"]["errors"].append(f"Directory walk failed for {d}: {e}")
            if len(candidate_files) >= 500:
                break

        # YARA scan (fast, static)
        for path in candidate_files:
            try:
                hits = await asyncio.to_thread(yara_scan_file, path)
                if hits:
                    results["yara"]["detections"].append({
                        "path": path,
                        "rule": hits[0].get("rule"),
                        "description": hits[0].get("description"),
                        "severity": hits[0].get("severity"),
                    })
            except Exception as e:
                results["yara"]["errors"].append(f"YARA scan failed for {path}: {e}")

        # ClamAV scan
        clamav_result = await clamav_scan_paths(candidate_files[:50])
        results["clamav"]["installed"] = clamav_result.installed
        results["clamav"]["detections"] = [
            {"path": d["path"], "malware_name": d["malware_name"]}
            for d in clamav_result.detections
        ]
        results["clamav"]["errors"] = clamav_result.errors
        if not clamav_result.installed:
            results["clamav"]["errors"].append("ClamAV is not installed or not available in PATH")

        # Calculate hashes for detected files
        for det in results["yara"]["detections"] + results["clamav"]["detections"]:
            path = det["path"]
            try:
                h = await asyncio.to_thread(self._hash_file_sync, path)
                if h:
                    results["hashes"].append({"path": path, "sha256": h})
            except Exception as e:
                logger.debug(f"Hash failed for {path}: {e}")

        return results

    def _hash_file_sync(self, path: str) -> str:
        sha256 = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()

    async def _enrich_findings(self, file_results: dict, network_results: dict) -> list[dict]:
        """Extract IOCs from findings and enrich with threat intelligence.

        Enriches IPs, hashes, domains, and URLs with VirusTotal + Shodan data.
        """
        enriched: list[dict] = []

        # Extract IOCs from detection context
        ioc_text = " ".join(
            [d.get("path", "") + " " + d.get("malware_name", "")
             for d in file_results.get("clamav", {}).get("detections", [])]
            + [d.get("path", "") + " " + d.get("rule", "")
               for d in file_results.get("yara", {}).get("detections", [])]
            + [str(h.get("ip", "")) for h in network_results.get("hosts", [])]
        )
        iocs = ioc_extractor.extract(ioc_text)

        # Enrich IPs (VirusTotal + Shodan)
        for ip in iocs.get("ips", []):
            if not ip or len(ip) < 7:
                continue
            try:
                result = await enrich_ip(ip)
                if result:
                    enriched.append({"indicator": ip, "type": "ip", "enrichment": result})
            except Exception as e:
                logger.debug(f"IOC enrichment failed for IP {ip}: {e}")

        # Enrich file hashes (VirusTotal)
        for file_hash in iocs.get("hashes", []):
            if not file_hash or len(file_hash) not in (32, 40, 64):
                continue
            try:
                result = await vt_check_hash(file_hash)
                if result:
                    enriched.append({"indicator": file_hash, "type": "hash", "enrichment": result})
            except Exception as e:
                logger.debug(f"IOC enrichment failed for hash {file_hash}: {e}")

        # Enrich domains (VirusTotal)
        for domain in iocs.get("domains", [])[:10]:  # Limit to avoid rate limits
            if not domain or len(domain) < 4:
                continue
            try:
                result = await vt_check_domain(domain)
                if result:
                    enriched.append({"indicator": domain, "type": "domain", "enrichment": result})
            except Exception as e:
                logger.debug(f"IOC enrichment failed for domain {domain}: {e}")

        # Enrich URLs (VirusTotal)
        for url in iocs.get("urls", [])[:5]:  # Limit to avoid rate limits
            if not url or len(url) < 8:
                continue
            try:
                result = await vt_check_url(url)
                if result:
                    enriched.append({"indicator": url, "type": "url", "enrichment": result})
            except Exception as e:
                logger.debug(f"IOC enrichment failed for URL {url}: {e}")

        logger.info(f"Enriched {len(enriched)} indicators from scan findings")
        return enriched

    async def _check_vulnerabilities(self, local_asset: dict, network_results: dict) -> dict:
        """Run vulnerability checks using Nuclei, software CVE mapping, and service fingerprints."""
        try:
            results = await asyncio.wait_for(
                run_vulnerability_scan(
                    local_asset=local_asset,
                    network_hosts=network_results.get("hosts", []),
                    exposed_services=local_asset.get("listening_ports", []),
                ),
                timeout=150.0,
            )
            return results
        except asyncio.TimeoutError:
            return {
                "tool_status": {"nuclei": {"installed": False, "reason": "vulnerability scan timed out"}},
                "findings": [],
                "errors": ["Vulnerability scan exceeded 150s timeout"],
                "scanned_hosts": [],
            }
        except Exception as e:
            logger.exception(f"Vulnerability scan failed: {e}")
            return {
                "tool_status": {"nuclei": {"installed": False, "reason": str(e)}},
                "findings": [],
                "errors": [f"Vulnerability scan error: {e}"],
                "scanned_hosts": [],
            }

    async def _correlate_and_create_incidents(
        self,
        task_id: str,
        file_results: dict,
        network_results: dict,
        enriched: list[dict],
        vuln_results: dict,
    ) -> None:
        """Convert scan results into SecurityFinding and Threat records."""
        # Malware findings
        for det in file_results.get("clamav", {}).get("detections", []):
            await self._record_finding(
                task_id,
                "malware_detection",
                "critical",
                f"ClamAV detected {det['malware_name']} in {det['path']}",
                affected_resource=det["path"],
                recommendation="Quarantine the file and investigate the affected endpoint.",
            )

        for det in file_results.get("yara", {}).get("detections", []):
            await self._record_finding(
                task_id,
                "yara_detection",
                det.get("severity", "high").lower(),
                f"YARA rule '{det['rule']}' matched in {det['path']}",
                affected_resource=det["path"],
                recommendation="Review the matched file and capture evidence.",
            )

        # Network findings
        for host in network_results.get("hosts", []):
            await self._record_finding(
                task_id,
                "network_host",
                "info",
                f"Discovered host {host.get('ip')} ({host.get('hostname', 'unknown')})",
                affected_resource=str(host.get("ip")),
                recommendation="Review unauthorized or unknown hosts on the network.",
            )

        # Vulnerability findings — include CVE ID and CVSS score in description
        for finding in vuln_results.get("findings", []):
            cve_id = finding.get("cve_id")
            cvss_score = finding.get("cvss_score")
            # Build enriched description with CVE/CVSS
            desc_parts = [finding.get("description", "")]
            if cve_id:
                desc_parts.append(f"CVE: {cve_id}")
            if cvss_score is not None:
                desc_parts.append(f"CVSS: {cvss_score}")
            enriched_desc = " | ".join(p for p in desc_parts if p)

            await self._record_finding(
                task_id,
                "vulnerability",
                finding.get("severity", "medium").lower(),
                f"[{finding.get('confidence', 'potential').upper()}] {finding['title']}",
                description=enriched_desc,
                affected_resource=finding.get("affected_resource"),
                recommendation=finding.get("recommendation"),
            )

        # If Nuclei is unavailable, record that as a scan note so the UI is honest
        nuclei_status = vuln_results.get("tool_status", {}).get("nuclei", {})
        if not nuclei_status.get("installed"):
            await self._record_finding(
                task_id,
                "tool_unavailable",
                "info",
                f"Vulnerability scanner unavailable: {nuclei_status.get('reason', 'Nuclei not installed')}",
                affected_resource=platform.node(),
                recommendation="Install Nuclei and ensure it is in PATH for deeper vulnerability checks.",
            )

    async def _record_finding(
        self,
        task_id: str,
        finding_type: str,
        severity: str,
        title: str,
        description: Optional[str] = None,
        affected_resource: Optional[str] = None,
        mitre_technique: Optional[str] = None,
        recommendation: Optional[str] = None,
    ) -> None:
        """Persist a SecurityFinding to the database."""
        try:
            db = AsyncSessionLocal()
            finding = SecurityFinding(
                task_id=task_id,
                finding_type=finding_type,
                severity=severity,
                title=title,
                description=description or title,
                affected_resource=affected_resource,
                mitre_technique=mitre_technique,
                recommendation=recommendation,
            )
            db.add(finding)
            await db.commit()
            await db.close()

            await self._broadcast({
                "event": "security_finding",
                "task_id": task_id,
                "finding": {
                    "type": finding_type,
                    "severity": severity,
                    "title": title,
                    "affected_resource": affected_resource,
                },
                "timestamp": datetime.utcnow().isoformat(),
            })
        except Exception as e:
            logger.error(f"Failed to record finding: {e}")

    async def _mark_task_complete(
        self,
        task_id: str,
        status: str,
        error: Optional[str] = None,
        eicar_verified: Optional[bool] = None,
    ) -> None:
        try:
            db = AsyncSessionLocal()
            result = await db.execute(select(AgentTask).where(AgentTask.id == task_id))
            task = result.scalar_one_or_none()
            if task:
                task.status = status
                task.error_message = error
                task.completed_at = datetime.utcnow()
                task.updated_at = datetime.utcnow()
                # Store eicar_verified in plan_json if applicable
                if eicar_verified is not None and hasattr(task, "plan_json") and task.plan_json:
                    task.plan_json["eicar_verified"] = eicar_verified
                await db.commit()
            await db.close()
        except Exception as e:
            logger.error(f"Failed to mark task {task_id} {status}: {e}")

    async def get_task_status(self, task_id: str) -> Optional[dict]:
        try:
            db = AsyncSessionLocal()
            result = await db.execute(select(AgentTask).where(AgentTask.id == task_id))
            task = result.scalar_one_or_none()
            if not task:
                return None

            exec_result = await db.execute(
                select(AgentExecution).where(AgentExecution.task_id == task_id)
            )
            execution = exec_result.scalar_one_or_none()

            findings_result = await db.execute(
                select(SecurityFinding).where(SecurityFinding.task_id == task_id)
            )
            findings = findings_result.scalars().all()

            await db.close()

            # Extract eicar_verified from plan_json if present
            plan = task.plan_json if hasattr(task, "plan_json") and task.plan_json else {}
            eicar_verified = plan.get("eicar_verified") if isinstance(plan, dict) else None

            return {
                "task_id": task.id,
                "status": task.status,
                "description": task.description,
                "created_at": task.created_at.isoformat() if task.created_at else None,
                "completed_at": task.completed_at.isoformat() if task.completed_at else None,
                "error": task.error_message,
                "eicar_verified": eicar_verified,
                "findings_count": len(findings),
                "findings": [
                    {
                        "type": f.finding_type,
                        "severity": f.severity,
                        "title": f.title,
                        "description": f.description,
                        "affected_resource": f.affected_resource,
                        "created_at": f.created_at.isoformat() if f.created_at else None,
                    }
                    for f in findings
                ],
                "execution": {
                    "id": execution.id,
                    "status": execution.status,
                    "duration_seconds": execution.duration_seconds,
                } if execution else None,
            }
        except Exception as e:
            logger.error(f"Failed to get task status: {e}")
            return None

    async def cancel_task(self, task_id: str) -> bool:
        task = self._running.get(task_id)
        if task and not task.done():
            task.cancel()
            return True
        return False


# Singleton instance used by API routes
security_orchestrator = SecurityOrchestrator()
