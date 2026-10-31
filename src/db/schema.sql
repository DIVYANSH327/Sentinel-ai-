-- Sentinel AI — Authorized AI-Assisted Security Research Platform
-- Relational Schema Definition (SQLite / PostgreSQL compatible)

CREATE TABLE IF NOT EXISTS operators (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('lead_researcher', 'security_reviewer', 'auditor')),
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS authorized_assets (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  target_host TEXT NOT NULL,
  ip_or_cidr TEXT NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('staging', 'isolated_lab', 'production_read_only')),
  owner_team TEXT NOT NULL,
  authorization_ref TEXT NOT NULL,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  verified_by TEXT,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scope_policies (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  authorization_ref TEXT NOT NULL,
  permitted_hosts_json TEXT NOT NULL,
  permitted_cidrs_json TEXT NOT NULL,
  allowed_categories_json TEXT NOT NULL,
  max_rate_limit_rpm INTEGER NOT NULL CHECK (max_rate_limit_rpm > 0 AND max_rate_limit_rpm <= 120),
  require_human_approval_for_intrusive BOOLEAN NOT NULL DEFAULT TRUE,
  expires_at TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS assessment_plans (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  objective TEXT NOT NULL,
  asset_id TEXT NOT NULL REFERENCES authorized_assets(id),
  policy_id TEXT NOT NULL REFERENCES scope_policies(id),
  generated_by_source TEXT NOT NULL CHECK (generated_by_source IN ('gemini_api', 'deterministic_fallback')),
  model_name TEXT NOT NULL,
  steps_json TEXT NOT NULL,
  safety_attestation TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS jobs (
  id TEXT PRIMARY KEY,
  asset_id TEXT NOT NULL REFERENCES authorized_assets(id),
  policy_id TEXT NOT NULL REFERENCES scope_policies(id),
  category TEXT NOT NULL CHECK (category IN ('passive_http_headers', 'static_code_analysis', 'intrusive_review_only')),
  target_host TEXT NOT NULL,
  code_snippet TEXT,
  rate_limit_rpm INTEGER NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('queued', 'pending_approval', 'claimed', 'completed', 'expired', 'rejected')),
  requires_approval BOOLEAN NOT NULL DEFAULT FALSE,
  approved_by TEXT,
  approved_at TEXT,
  claimed_by_agent_id TEXT,
  idempotency_claim_key TEXT UNIQUE,
  claimed_at TEXT,
  expires_at TEXT NOT NULL,
  result_summary_json TEXT,
  completed_at TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  job_id TEXT NOT NULL REFERENCES jobs(id),
  asset_id TEXT NOT NULL REFERENCES authorized_assets(id),
  title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
  category TEXT NOT NULL CHECK (category IN ('passive_http_headers', 'static_code_analysis')),
  cwe_id TEXT NOT NULL,
  evidence TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('open', 'remediation_planned', 'resolved')),
  discovered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS remediations (
  id TEXT PRIMARY KEY,
  finding_id TEXT NOT NULL REFERENCES findings(id),
  title TEXT NOT NULL,
  proposed_fix TEXT NOT NULL,
  config_or_code_diff TEXT NOT NULL,
  requires_human_approval BOOLEAN NOT NULL DEFAULT TRUE,
  approval_status TEXT NOT NULL CHECK (approval_status IN ('pending_approval', 'approved', 'rejected')),
  approved_by TEXT,
  approval_note TEXT,
  approved_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enrollment_codes (
  id TEXT PRIMARY KEY,
  code_hash TEXT NOT NULL UNIQUE,
  code_preview TEXT NOT NULL,
  target_hostname TEXT NOT NULL,
  linux_user TEXT NOT NULL,
  issued_by TEXT NOT NULL,
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  consumed_at TEXT,
  consumed_by_agent_id TEXT,
  status TEXT NOT NULL CHECK (status IN ('active', 'consumed', 'expired', 'revoked'))
);

CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  linux_user TEXT NOT NULL,
  uid INTEGER NOT NULL CHECK (uid >= 1000),
  version TEXT NOT NULL,
  os_info TEXT NOT NULL DEFAULT 'Kali GNU/Linux Rolling 2026.1 (x86_64)',
  service_account TEXT NOT NULL DEFAULT 'kali',
  systemd_autostart_enabled BOOLEAN NOT NULL DEFAULT TRUE,
  credential_fingerprint TEXT NOT NULL,
  credential_hash TEXT NOT NULL,
  polling_mode TEXT NOT NULL DEFAULT 'outbound_https_poll',
  status TEXT NOT NULL CHECK (status IN ('pending_heartbeat', 'waiting_poll', 'online', 'paused', 'disconnected', 'revoked', 'uninstalled')),
  heartbeat_verified_live BOOLEAN NOT NULL DEFAULT FALSE,
  current_job_id TEXT,
  current_job_status TEXT NOT NULL DEFAULT 'idle',
  last_heartbeat_at TEXT,
  last_poll_at TEXT,
  claimed_jobs_count INTEGER NOT NULL DEFAULT 0,
  completed_jobs_count INTEGER NOT NULL DEFAULT 0,
  enrolled_at TEXT NOT NULL,
  revoked_at TEXT,
  uninstalled_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT NOT NULL,
  decision TEXT NOT NULL CHECK (decision IN ('allowed', 'denied', 'approval_required')),
  summary TEXT NOT NULL,
  metadata_json TEXT NOT NULL
);
