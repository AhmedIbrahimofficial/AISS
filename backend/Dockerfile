# ═══════════════════════════════════════════════════════════════════════════════
# AISS — Multi-stage Production Dockerfile
# Stage 1: Builder  — installs all dependencies
# Stage 2: Runner   — minimal runtime image
# ═══════════════════════════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps for compiled packages (cryptography, psutil, opencv, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    libpq-dev \
    libmagic1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender-dev \
    libgomp1 \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip + install wheel
RUN pip install --upgrade pip wheel setuptools

# Copy requirements and install (cached layer if unchanged)
COPY requirements-prod.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements-prod.txt

# ── Stage 2: Runner ───────────────────────────────────────────────────
FROM python:3.12-slim AS runner

LABEL maintainer="AISS Team <support@aiss.io>"
LABEL version="2.0.0"
LABEL description="AISS - AI Intelligent Security System"

# Non-root user for security
RUN groupadd -r aiss && useradd -r -g aiss -d /app -s /sbin/nologin aiss

# Runtime system libraries
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    libglib2.0-0 \
    libsm6 \
    libxext6 \
    libxrender1 \
    libgomp1 \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source (excluding dev files)
COPY --chown=aiss:aiss . .

# Remove credential and dev files that should not be in image
RUN rm -f .env .env.* admin_passwords.txt fake_credentials.txt \
         fake_api_keys.txt *.txt.bak config.json.txt database.sql.txt && \
    rm -rf .git .pytest_cache __pycache__ tests/ *.pyc

# Create required directories with correct ownership
RUN mkdir -p logs/evidence data rules static && \
    chown -R aiss:aiss /app && \
    chmod 750 /app && \
    chmod 700 /app/logs /app/data

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

# Switch to non-root
USER aiss

# Expose port
EXPOSE 8000

# Production entrypoint via gunicorn + uvicorn workers
CMD ["gunicorn", "main:app", \
     "--worker-class", "uvicorn.workers.UvicornWorker", \
     "--workers", "4", \
     "--bind", "0.0.0.0:8000", \
     "--timeout", "120", \
     "--graceful-timeout", "30", \
     "--max-requests", "1000", \
     "--max-requests-jitter", "100", \
     "--access-logfile", "-", \
     "--error-logfile", "-", \
     "--log-level", "warning", \
     "--forwarded-allow-ips", "*"]
