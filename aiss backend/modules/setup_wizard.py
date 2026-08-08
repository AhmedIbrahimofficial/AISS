"""AISS — Setup Wizard (Popup Questions System)
Guides users through initial configuration via interactive popups.

When frontend is active, every question is served as a popup dialog.
Questions are grouped into steps so the frontend can show them
one at a time or as a multi-step wizard.

The wizard persists answers to .env automatically.
Frontend integration:
  - GET  /api/agents/setup/questions  → receives question definitions
  - POST /api/agents/setup/answers    → submits answers, .env updated
  - WS   /ws  broadcast: {event: "setup_question", question: {...}}
      → frontend shows popup automatically

Auto-injection: when a new module is added to AISS, its questions
are automatically discovered from the MODULE_QUESTIONS registry
and added to the wizard without any manual step.
"""
import json
import os
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional
from utils.logger import setup_logger

logger = setup_logger("setup_wizard")

ENV_FILE = Path(".env")

# ─────────────────────────────────────────────────────────────────────
# Question definition
# ─────────────────────────────────────────────────────────────────────

@dataclass
class Question:
    id:           str                        # unique ID = env variable name
    step:         str                        # wizard step group
    title:        str                        # popup title
    label:        str                        # question text
    type:         str = "text"              # text | password | select | multiselect | toggle | url | number
    placeholder:  str = ""
    default:      Any = ""
    required:     bool = False
    options:      list = field(default_factory=list)  # for select/multiselect
    help_text:    str = ""
    help_url:     str = ""
    depends_on:   str = ""                  # show only if this env var is set
    validation:   str = ""                  # regex pattern
    icon:         str = ""                  # emoji or icon name

    def to_dict(self) -> dict:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────
# All wizard questions — auto-discovered by step
# New modules add entries here to appear automatically in the wizard
# ─────────────────────────────────────────────────────────────────────

ALL_QUESTIONS: list[Question] = [

    # ── Step 1: Basic Setup ───────────────────────────────────────────
    Question(
        id="ENVIRONMENT", step="1_basic",
        title="Deployment Mode",
        label="How will you use AISS?",
        type="select",
        options=[
            {"value": "development", "label": "Development / Testing (local machine)"},
            {"value": "production",  "label": "Production (server deployment)"},
        ],
        default="development",
        required=True,
        icon="🏠",
    ),
    Question(
        id="APP_NAME", step="1_basic",
        title="System Name",
        label="What do you want to call this AISS instance?",
        type="text",
        placeholder="AISS",
        default="AISS",
        help_text="This name appears in alerts, reports and the dashboard.",
        icon="🏷️",
    ),
    Question(
        id="ALLOWED_ORIGINS", step="1_basic",
        title="Frontend URL",
        label="What URL will your dashboard be served from?",
        type="url",
        placeholder="http://localhost:3000",
        default="http://localhost:3000",
        help_text="Enter the URL of your Next.js or React frontend. "
                  "Use comma-separated values for multiple origins.",
        icon="🌐",
    ),

    # ── Step 2: Database ──────────────────────────────────────────────
    Question(
        id="DATABASE_URL", step="2_database",
        title="Database",
        label="Which database do you want to use?",
        type="select",
        options=[
            {"value": "sqlite+aiosqlite:///./logs/cybersecurity.db",
             "label": "SQLite — zero setup, local only (recommended for dev)"},
            {"value": "mysql",
             "label": "MySQL 8+ — recommended for production"},
            {"value": "postgresql",
             "label": "PostgreSQL 14+ — best for production"},
        ],
        default="sqlite+aiosqlite:///./logs/cybersecurity.db",
        required=True,
        help_text="SQLite requires no setup. For production, use MySQL or PostgreSQL.",
        icon="🗄️",
    ),

    # ── Step 3: AI Providers ──────────────────────────────────────────
    Question(
        id="ANTHROPIC_API_KEY", step="3_ai",
        title="Anthropic Claude",
        label="Enter your Anthropic API key (for Claude AI analysis)",
        type="password",
        placeholder="sk-ant-api03-...",
        help_text="Get your key at https://console.anthropic.com/settings/keys",
        help_url="https://console.anthropic.com/settings/keys",
        icon="🤖",
        validation=r"^(sk-ant-|$)",
    ),
    Question(
        id="OPENAI_API_KEY", step="3_ai",
        title="OpenAI GPT",
        label="Enter your OpenAI API key (for GPT-4 fallback)",
        type="password",
        placeholder="sk-proj-...",
        help_text="Get your key at https://platform.openai.com/api-keys",
        help_url="https://platform.openai.com/api-keys",
        icon="🧠",
    ),
    Question(
        id="GROQ_API_KEY", step="3_ai",
        title="Groq (Ultra-fast AI)",
        label="Enter your Groq API key for ultra-fast LLM inference (free tier available)",
        type="password",
        placeholder="gsk_...",
        help_text="Free tier available at https://console.groq.com/keys",
        help_url="https://console.groq.com/keys",
        icon="⚡",
    ),
    Question(
        id="OPENAI_MODEL", step="3_ai",
        title="Default AI Model",
        label="Which OpenAI model should AISS use?",
        type="select",
        options=[
            {"value": "gpt-4o-mini", "label": "GPT-4o Mini — fast & cheap (recommended)"},
            {"value": "gpt-4o",      "label": "GPT-4o — most capable"},
            {"value": "gpt-4-turbo", "label": "GPT-4 Turbo"},
        ],
        default="gpt-4o-mini",
        depends_on="OPENAI_API_KEY",
        icon="⚙️",
    ),

    # ── Step 4: Threat Intelligence ───────────────────────────────────
    Question(
        id="VIRUSTOTAL_API_KEY", step="4_threat_intel",
        title="VirusTotal",
        label="Enter your VirusTotal API key for malware/IP reputation",
        type="password",
        placeholder="64-character hex key",
        help_text="Free key at https://www.virustotal.com/gui/my-apikey",
        help_url="https://www.virustotal.com/gui/my-apikey",
        icon="🦠",
    ),
    Question(
        id="SHODAN_API_KEY", step="4_threat_intel",
        title="Shodan",
        label="Enter your Shodan API key for host intelligence",
        type="password",
        help_text="Get key at https://account.shodan.io/",
        help_url="https://account.shodan.io/",
        icon="🔍",
    ),
    Question(
        id="GEOIP_DB_PATH", step="4_threat_intel",
        title="GeoIP Database",
        label="Path to your MaxMind GeoLite2-City.mmdb file",
        type="text",
        placeholder="data/GeoLite2-City.mmdb",
        default="data/GeoLite2-City.mmdb",
        help_text="Download free at https://www.maxmind.com/en/geolite2/signup — "
                  "enables geographic IP mapping.",
        help_url="https://www.maxmind.com/en/geolite2/signup",
        icon="🌍",
    ),

    # ── Step 5: Alerts ────────────────────────────────────────────────
    Question(
        id="APPRISE_URLS", step="5_alerts",
        title="Alert Channels",
        label="Where should AISS send security alerts?",
        type="text",
        placeholder="ntfy://ntfy.sh/my-aiss-alerts",
        help_text=(
            "Enter Apprise URLs comma-separated. Examples:\n"
            "• ntfy (free, no signup): ntfy://ntfy.sh/my-unique-topic\n"
            "• Discord: discord://webhook_id/webhook_token\n"
            "• Slack: slack://TokenA/TokenB/TokenC/channel\n"
            "• Telegram: tgram://BotToken/ChatID\n"
            "• Email: mailtos://user:pass@smtp.gmail.com/to@email.com\n"
            "Leave blank to disable external alerts."
        ),
        icon="🔔",
    ),
    Question(
        id="ALERT_MIN_SEVERITY", step="5_alerts",
        title="Alert Threshold",
        label="Minimum threat severity to trigger an alert",
        type="select",
        options=[
            {"value": "low",      "label": "Low — alert on everything"},
            {"value": "medium",   "label": "Medium — medium, high and critical"},
            {"value": "high",     "label": "High — only high and critical (recommended)"},
            {"value": "critical", "label": "Critical — only the most severe"},
        ],
        default="high",
        icon="📊",
    ),

    # ── Step 6: Remote Monitoring ─────────────────────────────────────
    Question(
        id="_REMOTE_AGENTS_SETUP", step="6_remote_monitoring",
        title="Remote Agent Monitoring",
        label="Do you want to monitor other computers from this AISS server?",
        type="toggle",
        default=False,
        help_text=(
            "When enabled, you can connect other PCs, servers, or cloud VMs "
            "to this AISS instance. Each remote machine runs aiss_agent.py "
            "and forwards threats, metrics and events here.\n\n"
            "Works over: LAN (local network), WAN (internet), VPN, MAN."
        ),
        icon="🖥️",
    ),
    Question(
        id="AISS_SERVER_HOST", step="6_remote_monitoring",
        title="AISS Server Address",
        label="What IP/hostname should remote agents connect to?",
        type="text",
        placeholder="192.168.1.100 or your-domain.com",
        help_text="This is the address remote agents will use to connect. "
                  "For LAN: use your local IP. For WAN: use your public IP or domain.",
        depends_on="_REMOTE_AGENTS_SETUP",
        icon="🌐",
    ),

    # ── Step 7: Network Topology ──────────────────────────────────────
    Question(
        id="_NETWORK_TYPE", step="7_network",
        title="Network Type",
        label="What type of network is AISS deployed on?",
        type="select",
        options=[
            {"value": "lan",  "label": "LAN — Local Area Network (office/home)"},
            {"value": "wan",  "label": "WAN — Wide Area Network (internet-facing)"},
            {"value": "vpn",  "label": "VPN — Virtual Private Network (remote access)"},
            {"value": "man",  "label": "MAN — Metropolitan Area Network (multi-site)"},
            {"value": "hybrid", "label": "Hybrid — Mix of the above"},
        ],
        default="lan",
        help_text="This affects threat detection thresholds and alerting sensitivity.",
        icon="🌐",
    ),
    Question(
        id="SCAPY_DPI_ENABLED", step="7_network",
        title="Deep Packet Inspection",
        label="Enable Deep Packet Inspection (requires admin/root privileges)?",
        type="toggle",
        default=False,
        help_text="DPI inspects packet payloads for attack patterns using Scapy. "
                  "Requires admin privileges. Leave off if not running as root.",
        icon="🔬",
    ),

    # ── Step 8: AISS License ──────────────────────────────────────────
    Question(
        id="AISS_LICENSE_KEY", step="8_license",
        title="AISS License",
        label="Enter your AISS license key",
        type="password",
        placeholder="AISS-ENT-XXXX-XXXX-XXXX",
        help_text=(
            "License key determines your plan:\n"
            "• No key: 14-day trial (1 user, limited features)\n"
            "• Standard: 5 seats, full detection + response\n"
            "• Enterprise: unlimited seats, SSO, white-label\n"
            "\nGet a license at https://aiss.io/pricing"
        ),
        help_url="https://aiss.io/pricing",
        icon="🔑",
    ),

    # ── Step 9: Email ─────────────────────────────────────────────────
    Question(
        id="SMTP_HOST", step="9_email",
        title="Email Server",
        label="SMTP server hostname for email alerts and verification",
        type="text",
        placeholder="smtp.gmail.com",
        help_text="Used for user email verification and password reset emails.",
        icon="📧",
    ),
    Question(
        id="SMTP_USER", step="9_email",
        title="Email Username",
        label="SMTP username / email address",
        type="text",
        placeholder="alerts@your-domain.com",
        depends_on="SMTP_HOST",
        icon="👤",
    ),
    Question(
        id="SMTP_PASSWORD", step="9_email",
        title="Email Password",
        label="SMTP password or app password",
        type="password",
        depends_on="SMTP_HOST",
        icon="🔒",
    ),

    # ── Step 10: Advanced / Optional ─────────────────────────────────
    Question(
        id="SENTRY_DSN", step="10_advanced",
        title="Error Tracking (Sentry)",
        label="Sentry DSN for error monitoring (optional)",
        type="text",
        placeholder="https://key@sentry.io/id",
        help_text="Get free DSN at https://sentry.io",
        help_url="https://sentry.io",
        icon="🐛",
    ),
    Question(
        id="TAXII_SERVER_URL", step="10_advanced",
        title="STIX/TAXII Threat Feeds",
        label="TAXII server URL for live threat intelligence feeds",
        type="url",
        placeholder="https://cti-taxii.mitre.org/taxii/",
        default="https://cti-taxii.mitre.org/taxii/",
        help_text="MITRE ATT&CK TAXII server is pre-configured as default. "
                  "Leave as-is unless you have a private TAXII server.",
        icon="📡",
    ),
    Question(
        id="LOG_LEVEL", step="10_advanced",
        title="Log Verbosity",
        label="How verbose should AISS logs be?",
        type="select",
        options=[
            {"value": "DEBUG",   "label": "DEBUG — everything (dev only)"},
            {"value": "INFO",    "label": "INFO — normal operations"},
            {"value": "WARNING", "label": "WARNING — warnings and errors only"},
            {"value": "ERROR",   "label": "ERROR — errors only"},
        ],
        default="INFO",
        icon="📝",
    ),
]

# Steps metadata (for frontend wizard progress indicator)
STEPS = [
    {"id": "1_basic",             "title": "Basic Setup",            "icon": "🏠"},
    {"id": "2_database",          "title": "Database",               "icon": "🗄️"},
    {"id": "3_ai",                "title": "AI Providers",           "icon": "🤖"},
    {"id": "4_threat_intel",      "title": "Threat Intelligence",    "icon": "🔍"},
    {"id": "5_alerts",            "title": "Alerts",                 "icon": "🔔"},
    {"id": "6_remote_monitoring", "title": "Remote Monitoring",      "icon": "🖥️"},
    {"id": "7_network",           "title": "Network",                "icon": "🌐"},
    {"id": "8_license",           "title": "License",                "icon": "🔑"},
    {"id": "9_email",             "title": "Email",                  "icon": "📧"},
    {"id": "10_advanced",         "title": "Advanced",               "icon": "⚙️"},
]


class SetupWizard:
    """Manages wizard state, question delivery, and answer application."""

    def get_questions(self) -> dict:
        """Return all questions grouped by step, with current values pre-filled."""
        env = self._read_env()
        questions_by_step = {}
        for q in ALL_QUESTIONS:
            step = questions_by_step.setdefault(q.step, [])
            qd   = q.to_dict()
            # Pre-fill with current value
            current = env.get(q.id, "")
            qd["current_value"] = current if current else q.default
            step.append(qd)

        return {
            "steps":             STEPS,
            "questions_by_step": questions_by_step,
            "total_questions":   len(ALL_QUESTIONS),
            "completed":         self._count_completed(env),
            "wizard_version":    "2.0.0",
        }

    async def apply_answers(self, answers: dict) -> dict:
        """
        Apply wizard answers to .env file.
        Returns {applied: int, warnings: list, restart_required: bool}
        """
        env          = self._read_env()
        applied      = 0
        warnings     = []
        restart_keys = {
            "DATABASE_URL", "SECRET_KEY", "ENVIRONMENT",
            "AISS_LICENSE_KEY", "ALLOWED_ORIGINS",
        }
        restart_required = False

        for key, value in answers.items():
            if key.startswith("_"):   # internal wizard keys — skip
                continue
            old_val = env.get(key, "")
            if str(value) == str(old_val):
                continue   # unchanged
            env[key] = str(value)
            applied  += 1
            if key in restart_keys:
                restart_required = True

        # Write back
        self._write_env(env)

        # Apply immediately without restart where possible
        for key, value in answers.items():
            if not key.startswith("_"):
                os.environ[key] = str(value)

        logger.info(f"Setup wizard applied {applied} changes")
        return {
            "applied":          applied,
            "warnings":         warnings,
            "restart_required": restart_required,
            "message":          f"Applied {applied} setting(s) successfully."
                                + (" Restart AISS for changes to take effect."
                                   if restart_required else ""),
        }

    # ── .env helpers ────────────────────────────────────────────────

    def _read_env(self) -> dict:
        env = {}
        if not ENV_FILE.exists():
            return env
        for line in ENV_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
        return env

    def _write_env(self, env: dict) -> None:
        if not ENV_FILE.exists():
            return
        lines_out = []
        written   = set()
        for line in ENV_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                k = stripped.split("=", 1)[0].strip()
                if k in env:
                    lines_out.append(f"{k}={env[k]}")
                    written.add(k)
                    continue
            lines_out.append(line)

        # Append any new keys not in original file
        for k, v in env.items():
            if k not in written:
                lines_out.append(f"{k}={v}")

        ENV_FILE.write_text("\n".join(lines_out), encoding="utf-8")

    def _count_completed(self, env: dict) -> int:
        return sum(1 for q in ALL_QUESTIONS
                   if env.get(q.id, "").strip()
                   and not q.id.startswith("_"))


# ─────────────────────────────────────────────────────────────────────
# Auto-registration hook — called when a new module is added
# ─────────────────────────────────────────────────────────────────────

def register_module_questions(questions: list[Question]) -> None:
    """
    Called by new modules to inject their questions into the wizard.
    This ensures that when frontend is implemented, any new AISS module
    automatically gets its configuration questions shown as popups.
    """
    for q in questions:
        # Avoid duplicates
        if not any(existing.id == q.id for existing in ALL_QUESTIONS):
            ALL_QUESTIONS.append(q)
            logger.debug(f"Setup wizard: registered question '{q.id}' from module")


# Singleton
setup_wizard = SetupWizard()
