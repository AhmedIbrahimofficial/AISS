"""
AISS Credential Setup & Verification Script
Run this to check all external dependencies and get exact setup instructions.

Usage: python setup_credentials.py
"""
import os, sys, asyncio, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

W = "\033[93m"   # yellow
G = "\033[92m"   # green
R = "\033[91m"   # red
B = "\033[94m"   # blue
X = "\033[0m"    # reset

def ok(msg):   print(f"  {G}✅  {msg}{X}")
def warn(msg): print(f"  {W}⚠️   {msg}{X}")
def err(msg):  print(f"  {R}❌  {msg}{X}")
def info(msg): print(f"  {B}ℹ️   {msg}{X}")

print(f"\n{B}{'='*60}")
print(f"  AISS Credential & Dependency Status")
print(f"{'='*60}{X}\n")

# ── 1. Evidence Encryption Key ────────────────────────────────────────
key = os.environ.get("EVIDENCE_ENCRYPTION_KEY", "")
if key:
    ok(f"Evidence encryption key: SET ({key[:12]}...)")
else:
    warn("EVIDENCE_ENCRYPTION_KEY not set — generating one now...")
    from cryptography.fernet import Fernet
    new_key = Fernet.generate_key().decode()
    print(f"\n  Add this to your .env:")
    print(f"  {G}EVIDENCE_ENCRYPTION_KEY={new_key}{X}\n")

# ── 2. Redis / Celery ─────────────────────────────────────────────────
broker = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
ok(f"CELERY_BROKER_URL: {broker}")
try:
    import redis
    r = redis.Redis.from_url(broker, socket_connect_timeout=2)
    r.ping()
    ok("Redis server: RUNNING (ping OK)")
except Exception as e:
    err(f"Redis server: NOT REACHABLE — {e}")
    info("Install Memurai (Windows Redis): https://www.memurai.com/get-memurai")
    info("Or use WSL: wsl --install → sudo apt install redis → sudo service redis start")
    info("Celery tasks will queue when Redis comes online.")

# ── 3. GeoIP2 Database ────────────────────────────────────────────────
geoip_path = os.environ.get("GEOIP_DB_PATH",
    os.path.join(os.path.dirname(__file__), "data", "GeoLite2-City.mmdb"))
if os.path.exists(geoip_path):
    size_mb = os.path.getsize(geoip_path) / 1024 / 1024
    ok(f"GeoLite2-City.mmdb: FOUND ({size_mb:.1f} MB) at {geoip_path}")
else:
    err(f"GeoLite2-City.mmdb: NOT FOUND at {geoip_path}")
    print(f"""
  {W}To enable real geo-location for threat sources:{X}
  1. Register FREE at: https://www.maxmind.com/en/geolite2/signup
  2. Download GeoLite2-City.mmdb (MaxMind DB binary format)
  3. Place it at: {geoip_path}
     OR set GEOIP_DB_PATH=/your/path/GeoLite2-City.mmdb in .env

  {B}Quick download (after getting your MaxMind license key):{X}
  pip install geoipupdate
  Then configure /etc/GeoIP.conf with your AccountID and LicenseKey
""")

# ── 4. Apprise / Alerts ───────────────────────────────────────────────
apprise_urls = os.environ.get("APPRISE_URLS", "")
if apprise_urls:
    channels = [u.split("://")[0] for u in apprise_urls.split(",") if "://" in u]
    ok(f"APPRISE_URLS: configured ({', '.join(channels)})")
else:
    warn("APPRISE_URLS: not set — no external alerts")
    print(f"""
  {W}Quickest option (FREE, no account):{X}
  1. Pick a unique topic: e.g. aiss-alerts-funan-2024
  2. Add to .env:
     {G}APPRISE_URLS=ntfy://ntfy.sh/aiss-alerts-funan-2024{X}
  3. Subscribe on phone: install ntfy app → subscribe to topic
     OR browser: https://ntfy.sh/aiss-alerts-funan-2024
  4. Every CRITICAL/HIGH threat fires a push notification instantly.

  {W}For Telegram (popular choice):{X}
  1. Open Telegram → message @BotFather → /newbot → get token
  2. Get your chat ID: message @userinfobot
  3. Add to .env:
     {G}APPRISE_URLS=tgram://YOUR_BOT_TOKEN/YOUR_CHAT_ID{X}

  {W}For Discord:{X}
  1. Server Settings → Integrations → Webhooks → New Webhook → Copy URL
  2. URL format: https://discord.com/api/webhooks/ID/TOKEN
  3. Add to .env:
     {G}APPRISE_URLS=discord://ID/TOKEN{X}
""")

# ── 5. VirusTotal ─────────────────────────────────────────────────────
vt_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
if vt_key:
    ok(f"VIRUSTOTAL_API_KEY: SET ({vt_key[:8]}...)")
else:
    warn("VIRUSTOTAL_API_KEY: not set — IP/hash reputation disabled")
    print(f"""
  {W}VirusTotal FREE tier (1000 lookups/day):{X}
  1. Register at: https://www.virustotal.com/gui/join-us
  2. Go to: https://www.virustotal.com/gui/my-apikey
  3. Copy your API key and add to .env:
     {G}VIRUSTOTAL_API_KEY=your_64_char_key_here{X}
""")

# ── 6. Shodan ─────────────────────────────────────────────────────────
shodan_key = os.environ.get("SHODAN_API_KEY", "")
if shodan_key:
    ok(f"SHODAN_API_KEY: SET ({shodan_key[:8]}...)")
else:
    warn("SHODAN_API_KEY: not set — port/banner enrichment disabled")
    print(f"""
  {W}Shodan FREE tier:{X}
  1. Register at: https://account.shodan.io/register
  2. Go to: https://account.shodan.io
  3. Copy API key and add to .env:
     {G}SHODAN_API_KEY=your_key_here{X}
  Note: Free tier = 1 query credit/month. Paid = $49/mo for full access.
""")

# ── 7. Sentry ─────────────────────────────────────────────────────────
sentry_dsn = os.environ.get("SENTRY_DSN", "")
if sentry_dsn:
    ok(f"SENTRY_DSN: SET")
else:
    warn("SENTRY_DSN: not set — error tracking disabled")
    print(f"""
  {W}Sentry FREE tier (5000 errors/month):{X}
  1. Register at: https://sentry.io/signup/
  2. Create a project → Platform: Python → FastAPI
  3. Copy the DSN (looks like: https://abc@xyz.ingest.sentry.io/123)
  4. Add to .env:
     {G}SENTRY_DSN=https://your@dsn.ingest.sentry.io/project{X}
""")

# ── 8. TAXII/STIX ─────────────────────────────────────────────────────
taxii_url = os.environ.get("TAXII_SERVER_URL", "")
if taxii_url:
    ok(f"TAXII_SERVER_URL: SET ({taxii_url})")
else:
    info("TAXII_SERVER_URL: not set (optional — system works fine without)")
    print(f"""
  {B}Optional free TAXII feed:{X}
  MITRE ATT&CK TAXII server (public, no auth):
  {G}TAXII_SERVER_URL=https://cti-taxii.mitre.org/taxii/{X}
  TAXII_COLLECTION=Enterprise ATT&CK
""")

# ── Summary ───────────────────────────────────────────────────────────
print(f"\n{B}{'='*60}")
print(f"  Summary")
print(f"{'='*60}{X}")
configured = sum(bool(os.environ.get(k)) for k in [
    'EVIDENCE_ENCRYPTION_KEY','CELERY_BROKER_URL',
    'VIRUSTOTAL_API_KEY','SHODAN_API_KEY',
    'APPRISE_URLS','SENTRY_DSN','TAXII_SERVER_URL'
])
print(f"  {G}{configured}/7 credentials configured{X}")
if os.path.exists(geoip_path):
    print(f"  {G}GeoIP2 database: ready{X}")
else:
    print(f"  {W}GeoIP2 database: needs download{X}")

print(f"\n  App starts and runs without ANY of these.")
print(f"  Each one adds an extra capability when configured.\n")
