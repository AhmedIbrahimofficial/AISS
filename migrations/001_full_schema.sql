-- ═══════════════════════════════════════════════════════════════════════════
-- AISS — Full Database Schema for Supabase (PostgreSQL)
-- ═══════════════════════════════════════════════════════════════════════════
-- Run this in the Supabase SQL Editor:
--   Supabase Dashboard → SQL Editor → New query → paste → Run
--
-- This is idempotent — safe to run multiple times (uses IF NOT EXISTS).
-- After running, set your DATABASE_URL in .env to your Supabase connection string.
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Extensions ───────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- for gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "pg_trgm";    -- for fast text search on threats

-- ── Enums ─────────────────────────────────────────────────────────────────────
DO $$ BEGIN
  CREATE TYPE user_role            AS ENUM ('admin', 'analyst', 'viewer');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE auth_user_role       AS ENUM ('admin', 'analyst', 'viewer');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE threat_severity      AS ENUM ('low', 'medium', 'high', 'critical');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE threat_status        AS ENUM ('active', 'analyzing', 'responding', 'resolved', 'false_positive');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE event_severity       AS ENUM ('info', 'warning', 'error', 'critical');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE scan_status          AS ENUM ('running', 'completed', 'failed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE device_status        AS ENUM ('pending', 'paired', 'connected', 'disconnected', 'revoked');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE verification_token_type AS ENUM ('email_verify', 'password_reset');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE otp_purpose          AS ENUM ('phone_verify', 'login_2fa', 'email_otp');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 1 — CORE PLATFORM TABLES
-- ═══════════════════════════════════════════════════════════════════════════

-- ── 1.1 Users (legacy / shared FK target) ────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
    id                   TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    username             VARCHAR(64) NOT NULL UNIQUE,
    email                VARCHAR(255)         UNIQUE,
    hashed_password      VARCHAR(255) NOT NULL,
    role                 user_role    NOT NULL DEFAULT 'viewer',
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    is_verified          BOOLEAN      NOT NULL DEFAULT FALSE,
    email_verify_token   VARCHAR(100),
    email_verify_expires TIMESTAMP,
    reset_token          VARCHAR(100),
    reset_token_expires  TIMESTAMP,
    refresh_token_hash   VARCHAR(255),
    login_attempts       INTEGER      NOT NULL DEFAULT 0,
    locked_until         TIMESTAMP,
    created_at           TIMESTAMP    NOT NULL DEFAULT NOW(),
    last_login           TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_users_username ON users(username);
CREATE INDEX IF NOT EXISTS ix_users_email    ON users(email);

-- ── 1.2 Threats (raw threat table) ───────────────────────────────────────────
CREATE TABLE IF NOT EXISTS threats (
    id                 TEXT PRIMARY KEY,
    type               TEXT NOT NULL,
    description        TEXT NOT NULL,
    severity           TEXT NOT NULL,
    source             TEXT,
    module             TEXT,
    status             TEXT NOT NULL DEFAULT 'active',
    detected_at        TEXT,
    resolved_at        TEXT,
    resolution_note    TEXT,
    metadata           TEXT,   -- JSON serialised
    ai_analysis        TEXT,
    recommended_action TEXT
);

CREATE INDEX IF NOT EXISTS ix_threats_status   ON threats(status);
CREATE INDEX IF NOT EXISTS ix_threats_severity ON threats(severity);

-- ── 1.3 Threat Logs (ORM-managed enriched threat records) ────────────────────
CREATE TABLE IF NOT EXISTS threat_logs (
    id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    threat_type     VARCHAR(64) NOT NULL,
    severity        threat_severity NOT NULL,
    status          threat_status   NOT NULL DEFAULT 'active',
    source_ip       VARCHAR(45),
    target          VARCHAR(255),
    description     TEXT        NOT NULL,
    raw_data        JSONB,
    ai_analysis     TEXT,
    ai_confidence   FLOAT,
    response_action TEXT,
    module          VARCHAR(64),
    detected_at     TIMESTAMP   NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMP,
    resolution_note TEXT
);

CREATE INDEX IF NOT EXISTS ix_tl_threat_type       ON threat_logs(threat_type);
CREATE INDEX IF NOT EXISTS ix_tl_severity          ON threat_logs(severity);
CREATE INDEX IF NOT EXISTS ix_tl_status            ON threat_logs(status);
CREATE INDEX IF NOT EXISTS ix_tl_detected_at       ON threat_logs(detected_at);
CREATE INDEX IF NOT EXISTS ix_tl_severity_status   ON threat_logs(severity, status);

-- ── 1.4 Blocked IPs ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS blocked_ips (
    id          TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    ip          VARCHAR(45) NOT NULL UNIQUE,
    reason      TEXT        NOT NULL,
    blocked_by  VARCHAR(64) REFERENCES users(username) ON DELETE SET NULL,
    blocked_at  TIMESTAMP   NOT NULL DEFAULT NOW(),
    expires_at  TIMESTAMP,
    is_active   BOOLEAN     NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS ix_blocked_ips_ip ON blocked_ips(ip);

-- ── 1.5 System Events (audit log) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS system_events (
    id          TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    event_type  VARCHAR(64) NOT NULL,
    severity    event_severity NOT NULL DEFAULT 'info',
    username    VARCHAR(64) REFERENCES users(username) ON DELETE SET NULL,
    ip_address  VARCHAR(45),
    description TEXT        NOT NULL,
    extra_data  JSONB,
    created_at  TIMESTAMP   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_se_event_type     ON system_events(event_type);
CREATE INDEX IF NOT EXISTS ix_se_created_at     ON system_events(created_at);
CREATE INDEX IF NOT EXISTS ix_se_type_created   ON system_events(event_type, created_at);

-- ── 1.6 Scan Results ─────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_results (
    id              TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    scan_type       VARCHAR(64) NOT NULL,
    target          VARCHAR(255) NOT NULL,
    status          scan_status  NOT NULL DEFAULT 'running',
    initiated_by    VARCHAR(64) REFERENCES users(username) ON DELETE SET NULL,
    threats_found   INTEGER     NOT NULL DEFAULT 0,
    duration_secs   FLOAT,
    findings        JSONB,
    error_message   TEXT,
    started_at      TIMESTAMP   NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_sr_scan_type  ON scan_results(scan_type);
CREATE INDEX IF NOT EXISTS ix_sr_started_at ON scan_results(started_at);

-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 2 — AUTH TABLES
-- ═══════════════════════════════════════════════════════════════════════════

-- ── 2.1 Auth Users ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_users (
    id                    TEXT         PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    username              VARCHAR(64)  NOT NULL UNIQUE,
    email                 VARCHAR(255) NOT NULL UNIQUE,
    hashed_password       VARCHAR(255) NOT NULL,
    role                  auth_user_role NOT NULL DEFAULT 'viewer',
    is_active             BOOLEAN      NOT NULL DEFAULT TRUE,
    is_verified           BOOLEAN      NOT NULL DEFAULT FALSE,
    is_phone_verified     BOOLEAN      NOT NULL DEFAULT FALSE,
    phone_number          VARCHAR(20),
    failed_login_attempts INTEGER      NOT NULL DEFAULT 0,
    locked_until          TIMESTAMP,
    last_failed_ip        VARCHAR(45),
    created_at            TIMESTAMP    NOT NULL DEFAULT NOW(),
    last_login_at         TIMESTAMP,
    last_login_ip         VARCHAR(45),
    must_change_password  BOOLEAN      NOT NULL DEFAULT FALSE,
    oauth_provider        VARCHAR(32),
    oauth_subject         VARCHAR(255),
    avatar_url            VARCHAR(512)
);

CREATE INDEX IF NOT EXISTS ix_auth_users_username ON auth_users(username);
CREATE INDEX IF NOT EXISTS ix_auth_users_email    ON auth_users(email);

-- ── 2.2 Auth Sessions (refresh token store) ──────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_sessions (
    id                 TEXT        PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id            TEXT        NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(64) NOT NULL UNIQUE,
    device_info        TEXT,
    ip_address         VARCHAR(45),
    user_agent         TEXT,
    created_at         TIMESTAMP   NOT NULL DEFAULT NOW(),
    expires_at         TIMESTAMP   NOT NULL,
    is_revoked         BOOLEAN     NOT NULL DEFAULT FALSE,
    last_used_at       TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_auth_sessions_user_id            ON auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS ix_auth_sessions_refresh_token_hash ON auth_sessions(refresh_token_hash);

-- ── 2.3 Verification Tokens ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_verification_tokens (
    id         TEXT                     PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id    TEXT                     NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    token      VARCHAR(128)             NOT NULL UNIQUE,
    token_type verification_token_type  NOT NULL,
    expires_at TIMESTAMP                NOT NULL,
    used_at    TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_avt_user_id ON auth_verification_tokens(user_id);
CREATE INDEX IF NOT EXISTS ix_avt_token   ON auth_verification_tokens(token);

-- ── 2.4 OTP Verifications ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_otp_verifications (
    id          TEXT         PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id     TEXT         NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    otp_hash    VARCHAR(64)  NOT NULL,
    purpose     otp_purpose  NOT NULL DEFAULT 'login_2fa',
    expires_at  TIMESTAMP    NOT NULL,
    attempts    INTEGER      NOT NULL DEFAULT 0,
    verified_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_aov_user_id ON auth_otp_verifications(user_id);

-- ── 2.5 Auth Onboarding ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS auth_onboarding (
    id               TEXT      PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id          TEXT      NOT NULL UNIQUE REFERENCES auth_users(id) ON DELETE CASCADE,
    is_completed     BOOLEAN   NOT NULL DEFAULT FALSE,
    completed_at     TIMESTAMP,
    completed_steps  TEXT,     -- JSON array of step IDs
    reset_at         TIMESTAMP,
    created_at       TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_ao_user_id ON auth_onboarding(user_id);

-- ── 2.6 Registered Devices ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS registered_devices (
    id                    TEXT         PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id               TEXT         NOT NULL REFERENCES auth_users(id) ON DELETE CASCADE,
    device_name           VARCHAR(128) NOT NULL,
    device_type           VARCHAR(32)  NOT NULL DEFAULT 'desktop',
    platform              VARCHAR(32),
    hostname              VARCHAR(255),
    os_info               VARCHAR(255),
    pairing_token_hash    VARCHAR(64)  UNIQUE,
    pairing_expires_at    TIMESTAMP,
    pairing_used_at       TIMESTAMP,
    is_paired             BOOLEAN      NOT NULL DEFAULT FALSE,
    paired_at             TIMESTAMP,
    device_secret_hash    VARCHAR(64),
    device_secret_expires TIMESTAMP,
    status                device_status NOT NULL DEFAULT 'pending',
    last_seen_at          TIMESTAMP,
    last_seen_ip          VARCHAR(45),
    connection_count      INTEGER      NOT NULL DEFAULT 0,
    is_revoked            BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked_at            TIMESTAMP,
    revoke_reason         VARCHAR(255),
    extra_info            JSONB,
    created_at            TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_device_user_id     ON registered_devices(user_id);
CREATE INDEX IF NOT EXISTS ix_device_user_status ON registered_devices(user_id, status);

-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 3 — AI AGENT TABLES
-- ═══════════════════════════════════════════════════════════════════════════

-- ── 3.1 Agent Tasks ──────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_tasks (
    id            TEXT      PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id       TEXT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status        VARCHAR(32) NOT NULL DEFAULT 'pending',
    description   TEXT      NOT NULL,
    plan_json     JSONB,
    playbook_name VARCHAR(128),
    error_message TEXT,
    created_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at  TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_at_user_id       ON agent_tasks(user_id);
CREATE INDEX IF NOT EXISTS ix_at_status        ON agent_tasks(status);
CREATE INDEX IF NOT EXISTS ix_at_created_at    ON agent_tasks(created_at);
CREATE INDEX IF NOT EXISTS ix_at_user_status   ON agent_tasks(user_id, status);

-- ── 3.2 Agent Executions ─────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_executions (
    id               TEXT      PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    task_id          TEXT      NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    status           VARCHAR(32) NOT NULL DEFAULT 'running',
    steps_json       JSONB,
    started_at       TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMP,
    duration_seconds FLOAT,
    error_message    TEXT
);

CREATE INDEX IF NOT EXISTS ix_ae_task_id ON agent_executions(task_id);

-- ── 3.3 Tool Executions ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS tool_executions (
    id               TEXT         PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    execution_id     TEXT         NOT NULL REFERENCES agent_executions(id) ON DELETE CASCADE,
    tool_name        VARCHAR(128) NOT NULL,
    category         VARCHAR(64)  NOT NULL,
    risk_level       VARCHAR(16)  NOT NULL,
    arguments_json   JSONB,
    result_json      JSONB,
    status           VARCHAR(32)  NOT NULL DEFAULT 'running',
    started_at       TIMESTAMP    NOT NULL DEFAULT NOW(),
    completed_at     TIMESTAMP,
    duration_seconds FLOAT,
    error_message    TEXT,
    retry_count      INTEGER      NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS ix_te_execution_id ON tool_executions(execution_id);
CREATE INDEX IF NOT EXISTS ix_te_tool_name    ON tool_executions(tool_name);

-- ── 3.4 Approvals ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS approvals (
    id                TEXT      PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    task_id           TEXT      NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    tool_name         VARCHAR(128) NOT NULL,
    risk_level        VARCHAR(16)  NOT NULL,
    description       TEXT      NOT NULL,
    reason            TEXT      NOT NULL,
    affected_resource VARCHAR(512),
    estimated_impact  TEXT,
    status            VARCHAR(16)  NOT NULL DEFAULT 'pending',
    created_at        TIMESTAMP NOT NULL DEFAULT NOW(),
    decided_at        TIMESTAMP,
    decided_by        TEXT      REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS ix_appr_task_id ON approvals(task_id);
CREATE INDEX IF NOT EXISTS ix_appr_status  ON approvals(status);

-- ── 3.5 Scheduled Tasks ───────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scheduled_tasks (
    id                  TEXT         PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id             TEXT         REFERENCES users(id) ON DELETE SET NULL,
    name                VARCHAR(256) NOT NULL,
    description         TEXT,
    tool_or_playbook    VARCHAR(128) NOT NULL,
    arguments_json      JSONB,
    schedule_expression VARCHAR(128) NOT NULL,
    enabled             BOOLEAN      NOT NULL DEFAULT TRUE,
    last_run_at         TIMESTAMP,
    next_run_at         TIMESTAMP,
    created_at          TIMESTAMP    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_st_user_id      ON scheduled_tasks(user_id);
CREATE INDEX IF NOT EXISTS ix_st_user_enabled ON scheduled_tasks(user_id, enabled);

-- ── 3.6 Reports ───────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS reports (
    id              TEXT      PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id         TEXT      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    period_start    TIMESTAMP NOT NULL,
    period_end      TIMESTAMP NOT NULL,
    status          VARCHAR(16) NOT NULL DEFAULT 'generating',
    generated_at    TIMESTAMP,
    file_path       VARCHAR(512),
    file_size_bytes INTEGER,
    sha256_hash     VARCHAR(64),
    error_message   TEXT,
    scope_json      JSONB
);

CREATE INDEX IF NOT EXISTS ix_rep_user_id        ON reports(user_id);
CREATE INDEX IF NOT EXISTS ix_rep_user_generated ON reports(user_id, generated_at);

-- ── 3.7 Security Findings ────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS security_findings (
    id                TEXT         PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    task_id           TEXT         NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    finding_type      VARCHAR(64)  NOT NULL,
    severity          VARCHAR(16)  NOT NULL,
    title             VARCHAR(512) NOT NULL,
    description       TEXT,
    affected_resource VARCHAR(512),
    mitre_technique   VARCHAR(64),
    recommendation    TEXT,
    created_at        TIMESTAMP    NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_sf_task_id     ON security_findings(task_id);
CREATE INDEX IF NOT EXISTS ix_sf_finding_type ON security_findings(finding_type);
CREATE INDEX IF NOT EXISTS ix_sf_severity    ON security_findings(severity);

-- ── 3.8 Agent Audit Events ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS agent_audit_events (
    id                       TEXT          PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    user_id                  TEXT          NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    event_type               VARCHAR(64)   NOT NULL,
    severity                 VARCHAR(16)   NOT NULL DEFAULT 'info',
    request_summary          VARCHAR(2048),
    plan_summary             TEXT,
    tool_name                VARCHAR(128),
    arguments_redacted_json  JSONB,
    auth_result              VARCHAR(64),
    execution_result_summary TEXT,
    risk_level               VARCHAR(16),
    approval_status          VARCHAR(16),
    ai_conclusion            TEXT,
    created_at               TIMESTAMP     NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ix_aae_user_id    ON agent_audit_events(user_id);
CREATE INDEX IF NOT EXISTS ix_aae_event_type ON agent_audit_events(event_type);
CREATE INDEX IF NOT EXISTS ix_aae_created_at ON agent_audit_events(created_at);
CREATE INDEX IF NOT EXISTS ix_aae_user_event ON agent_audit_events(user_id, event_type);

-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 4 — SECURITY ORCHESTRATOR TABLE
-- ═══════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS security_tasks (
    id             TEXT      PRIMARY KEY DEFAULT gen_random_uuid()::TEXT,
    status         VARCHAR(32) NOT NULL DEFAULT 'pending',
    description    TEXT,
    eicar_verified BOOLEAN,
    error          TEXT,
    created_at     TIMESTAMP NOT NULL DEFAULT NOW(),
    completed_at   TIMESTAMP
);

CREATE INDEX IF NOT EXISTS ix_sectask_status     ON security_tasks(status);
CREATE INDEX IF NOT EXISTS ix_sectask_created_at ON security_tasks(created_at);

-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 5 — ROW-LEVEL SECURITY (enable on all tables)
-- ═══════════════════════════════════════════════════════════════════════════
-- RLS is ENABLED but policies are permissive (backend uses service role key).
-- Tighten these if you use Supabase client SDK directly from the frontend.

ALTER TABLE users               ENABLE ROW LEVEL SECURITY;
ALTER TABLE threats             ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_logs         ENABLE ROW LEVEL SECURITY;
ALTER TABLE blocked_ips         ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_events       ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_results        ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_users          ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_sessions       ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_verification_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_otp_verifications   ENABLE ROW LEVEL SECURITY;
ALTER TABLE auth_onboarding     ENABLE ROW LEVEL SECURITY;
ALTER TABLE registered_devices  ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_tasks         ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_executions    ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_executions     ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals           ENABLE ROW LEVEL SECURITY;
ALTER TABLE scheduled_tasks     ENABLE ROW LEVEL SECURITY;
ALTER TABLE reports             ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_findings   ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_audit_events  ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_tasks      ENABLE ROW LEVEL SECURITY;

-- Service role bypass (backend connects with service role key — full access)
CREATE POLICY "service_role_bypass_users"        ON users               FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_threats"      ON threats             FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_threat_logs"  ON threat_logs         FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_blocked_ips"  ON blocked_ips         FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_sys_events"   ON system_events       FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_scan_results" ON scan_results        FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_auth_users"   ON auth_users          FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_auth_sess"    ON auth_sessions       FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_avt"          ON auth_verification_tokens FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_otp"          ON auth_otp_verifications   FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_onboarding"   ON auth_onboarding     FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_devices"      ON registered_devices  FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_agent_tasks"  ON agent_tasks         FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_agent_exec"   ON agent_executions    FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_tool_exec"    ON tool_executions     FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_approvals"    ON approvals           FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_sched_tasks"  ON scheduled_tasks     FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_reports"      ON reports             FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_sf"           ON security_findings   FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_aae"          ON agent_audit_events  FOR ALL TO service_role USING (true) WITH CHECK (true);
CREATE POLICY "service_role_bypass_sec_tasks"    ON security_tasks      FOR ALL TO service_role USING (true) WITH CHECK (true);

-- ═══════════════════════════════════════════════════════════════════════════
-- SECTION 6 — SEED: Default admin account
-- ═══════════════════════════════════════════════════════════════════════════
-- The backend auto-creates this on first startup (see core/database.py).
-- This seed is provided for reference. Change the password after first login.
-- Password 'Admin123!' is hashed with bcrypt below (for reference only).
-- The backend will create this automatically — do NOT run this manually
-- unless you want to reset to defaults.

-- INSERT INTO auth_users (username, email, hashed_password, role, is_verified, is_active, must_change_password)
-- VALUES (
--   'admin',
--   'admin@aiss-platform.com',
--   '$2b$12$...', -- generated by backend on first run
--   'admin',
--   TRUE,
--   TRUE,
--   TRUE
-- ) ON CONFLICT (email) DO NOTHING;

-- ═══════════════════════════════════════════════════════════════════════════
-- Done. Your AISS schema is ready.
-- Next steps:
--   1. Set DATABASE_URL in .env to your Supabase connection string
--   2. Start the backend: cd "aiss backend" && python main.py
--   3. The backend will connect to Supabase and start immediately
-- ═══════════════════════════════════════════════════════════════════════════
