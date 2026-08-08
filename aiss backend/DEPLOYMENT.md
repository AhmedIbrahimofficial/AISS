# AISS — Production Deployment Guide

## Docker Deployment (Recommended)

### 1. Prerequisites
```bash
# Install Docker + Docker Compose
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
```

### 2. Configure
```bash
cp .env.production.example .env
# Fill in required values:
# - DATABASE_URL (PostgreSQL)
# - SECRET_KEY (generate: python -c "import secrets; print(secrets.token_hex(64))")
# - EVIDENCE_ENCRYPTION_KEY
# - ANTHROPIC_API_KEY or OPENAI_API_KEY
# - AISS_LICENSE_KEY
```

### 3. TLS Certificates
```bash
# Option A: Let's Encrypt (recommended)
certbot certonly --standalone -d your-domain.com
cp /etc/letsencrypt/live/your-domain.com/fullchain.pem deploy/nginx/ssl/
cp /etc/letsencrypt/live/your-domain.com/privkey.pem deploy/nginx/ssl/

# Option B: Self-signed (dev/internal only)
openssl req -x509 -newkey rsa:4096 -keyout deploy/nginx/ssl/privkey.pem \
    -out deploy/nginx/ssl/fullchain.pem -days 365 -nodes \
    -subj "/CN=your-domain.com"
```

### 4. Update Nginx config
```bash
sed -i 's/YOUR_DOMAIN/your-domain.com/g' deploy/nginx/aiss.conf
```

### 5. Deploy
```bash
# Add POSTGRES_PASSWORD and REDIS_PASSWORD to .env
echo "POSTGRES_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_hex(16))')" >> .env
echo "REDIS_PASSWORD=$(python3 -c 'import secrets; print(secrets.token_hex(16))')" >> .env

docker-compose up -d
docker-compose logs -f aiss
```

### 6. Run migrations
```bash
docker-compose exec aiss alembic upgrade head
```

---

## Bare Metal / VM Deployment

### Systemd service (Linux)

```bash
sudo nano /etc/systemd/system/aiss.service
```

```ini
[Unit]
Description=AISS - AI Intelligent Security System
After=network.target redis.service postgresql.service
Wants=redis.service

[Service]
Type=exec
User=aiss
Group=aiss
WorkingDirectory=/opt/aiss/aiss backend
Environment=PYTHONPATH=/opt/aiss/aiss backend
ExecStart=/opt/aiss/aiss backend/.venv/bin/gunicorn main:app \
    --worker-class uvicorn.workers.UvicornWorker \
    --workers 4 \
    --bind 127.0.0.1:8000 \
    --timeout 120 \
    --max-requests 1000 \
    --max-requests-jitter 100 \
    --log-level warning
ExecReload=/bin/kill -s HUP $MAINPID
Restart=on-failure
RestartSec=5
EnvironmentFile=/opt/aiss/aiss backend/.env
StandardOutput=journal
StandardError=journal
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ReadWritePaths=/opt/aiss/aiss backend/logs /opt/aiss/aiss backend/data

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now aiss
sudo systemctl status aiss
```

### Celery worker service

```ini
[Unit]
Description=AISS Celery Worker
After=redis.service

[Service]
Type=exec
User=aiss
WorkingDirectory=/opt/aiss/aiss backend
ExecStart=/opt/aiss/aiss backend/.venv/bin/celery -A modules.celery_app worker \
    --loglevel=warning --concurrency=4 --queues=scan,ai,intel
EnvironmentFile=/opt/aiss/aiss backend/.env
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## Database Migrations

```bash
# Check current state
alembic current

# Upgrade to latest
alembic upgrade head

# Create a new migration
alembic revision --autogenerate -m "describe_change"

# Rollback one step
alembic downgrade -1
```

---

## Monitoring

### Prometheus + Grafana

AISS exposes `/metrics` (restricted to internal network in nginx config).

```yaml
# prometheus.yml scrape config
scrape_configs:
  - job_name: aiss
    static_configs:
      - targets: ['localhost:8000']
    metrics_path: /metrics
    scheme: http
```

Key metrics:
- `aiss_threats_total{severity, type}` — threat counter
- `aiss_threats_active` — active threat gauge
- `aiss_scan_duration_seconds{module}` — scan performance
- `aiss_llm_tokens_total{provider, direction}` — LLM usage/cost
- `aiss_anomaly_score` — ML anomaly distribution
- `aiss_blocked_ips_total` — blocked IP count

### Health endpoint

```bash
curl https://your-domain.com/api/health
# Returns: status, uptime, CPU, RAM, disk, process count
```

---

## Backup

```bash
# Database
pg_dump -U aiss_user aiss_db > backup_$(date +%Y%m%d).sql

# Evidence files
tar -czf evidence_$(date +%Y%m%d).tar.gz logs/evidence/

# ChromaDB vectors
tar -czf chroma_$(date +%Y%m%d).tar.gz data/chroma_db/

# River model
cp data/online_model.pkl data/online_model_$(date +%Y%m%d).pkl
```

---

## Scaling

### Horizontal scaling (multiple AISS instances)

Requirements:
- Shared PostgreSQL database
- Shared Redis instance
- Shared NFS/S3 for `data/` and `logs/` directories
- Load balancer with sticky sessions for WebSocket connections

```nginx
upstream aiss_cluster {
    ip_hash;  # sticky sessions for WebSocket
    server aiss1:8000;
    server aiss2:8000;
    server aiss3:8000;
}
```

### GPU acceleration (for local LLM)

Set `LLAMA_MODEL_PATH` to a GGUF model and install llama-cpp-python with CUDA:
```bash
CMAKE_ARGS="-DGGML_CUDA=on" pip install llama-cpp-python --force-reinstall
```

---

## Upgrade

```bash
git pull origin main
pip install -r requirements.txt
alembic upgrade head
sudo systemctl restart aiss
sudo systemctl restart aiss-celery
```

---

## Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `402 License required` | No valid license | Set `AISS_LICENSE_KEY` in .env |
| `503 Database unavailable` | DB not started | Check DB service, verify DATABASE_URL |
| `AI analysis returns fallback` | No LLM key | Set at least one of ANTHROPIC_API_KEY / OPENAI_API_KEY |
| High memory usage | ML models loaded | Set DISABLE_YOLO=1, reduce WORKERS count |
| WebSocket disconnects | Nginx timeout | Increase `proxy_read_timeout` in nginx config |
| Celery tasks not processing | Redis down | Check Redis service, verify CELERY_BROKER_URL |
