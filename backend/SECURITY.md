# AISS — Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

Email: security@aiss.io  
PGP key: Available at https://aiss.io/.well-known/security.txt  
Response time: 48 hours for acknowledgement, 14 days for patch

Please include:
- Description and impact
- Steps to reproduce
- Affected versions
- Optional: proof-of-concept (no live exploitation)

---

## Security Architecture

### Authentication
- **JWT access tokens** — HS256, configurable expiry (default 15 min)
- **Opaque refresh tokens** — 128-byte random, SHA-256 hashed in DB, rotated on use
- **Argon2id password hashing** — OWASP-recommended parameters (64MB memory, 2 iterations)
- **Brute-force protection** — account lockout after N failed attempts (configurable)
- **Email verification** — required before login
- **Session management** — per-device sessions, revocable individually

### Transport Security
- **TLS 1.2+ enforced** via Nginx reverse proxy in production
- **HSTS** with `max-age=63072000; includeSubDomains; preload`
- **Certificate pinning** supported via `truststore`

### API Security
- **Rate limiting** — global (200/min), per-endpoint, auth endpoints (10/min)
- **Request size limit** — 50MB default (configurable `MAX_REQUEST_BODY_BYTES`)
- **CORS** — explicit origin allowlist only
- **CSRF** — mitigated via SameSite cookie policy and token-based auth
- **Input sanitization** — path traversal, null bytes, injection probes blocked at middleware layer
- **SQL injection** — SQLAlchemy ORM with parameterised queries throughout
- **XSS** — CSP headers, output is JSON (no HTML rendering from user input)
- **SSRF** — external HTTP calls only made for configured services (VT, Shodan, etc.)

### Security Headers (every response)
```
Content-Security-Policy: default-src 'self'; frame-ancestors 'none'; ...
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload (production)
```

### Secret Management
- All secrets from environment variables — never hardcoded
- Automatic secure key generation at first startup
- Keys persisted in `data/secrets.json` (mode 600, gitignored)
- Startup validation blocks launch if required keys are insecure defaults

### Evidence Security
- All forensic evidence encrypted at rest with Fernet (AES-128-CBC + HMAC)
- Evidence key configurable via `EVIDENCE_ENCRYPTION_KEY`
- Auto-generated key if unset (not persistent across restarts — set in production)
- Evidence directory permissions restricted to application user

### License Anti-Tampering
- License signatures validated with HMAC-SHA256
- Device binding via hardware fingerprint
- Offline validation for air-gapped deployments
- Cache invalidation on server-side revocation

---

## Secure Deployment Checklist

Before going to production:

- [ ] Set `ENVIRONMENT=production` in `.env`
- [ ] Generate `SECRET_KEY` with `python -c "import secrets; print(secrets.token_hex(64))"`
- [ ] Generate `EVIDENCE_ENCRYPTION_KEY` with `from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())`
- [ ] Set explicit `ALLOWED_ORIGINS` (not wildcard)
- [ ] Use PostgreSQL or MySQL (not SQLite)
- [ ] Configure Redis with password (`REDIS_PASSWORD`)
- [ ] Enable TLS via Nginx with valid certificate
- [ ] Set `AISS_LICENSE_KEY` for commercial use
- [ ] Restrict file permissions: `chmod 700 data/ logs/`
- [ ] Run behind firewall — only expose 80/443
- [ ] Set `LOG_FORMAT=json` and ship logs to SIEM
- [ ] Configure `SENTRY_DSN` for error tracking
- [ ] Run `bandit -r . -ll` before each release
- [ ] Run `safety check -r requirements.txt` before each release

---

## Dependency Security

Run before each release:
```bash
# Vulnerability scan
safety check -r requirements.txt

# Static analysis
bandit -r . -ll -x .venv,tests

# License compliance
pip-licenses --format=table
```

---

## Data Privacy

- Threat metadata may contain IP addresses — treat as PII in GDPR jurisdictions
- Evidence files are encrypted — require key to read
- Logs contain IP addresses — implement log retention policy
- No user data sent to external services except configured integrations (VT, Shodan, etc.)
