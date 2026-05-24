CREATE TABLE IF NOT EXISTS tenants (
  tenant_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  plan TEXT NOT NULL,
  body JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agents (
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  agent_id TEXT NOT NULL,
  owner TEXT NOT NULL,
  status TEXT NOT NULL,
  body JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, agent_id)
);

CREATE TABLE IF NOT EXISTS missions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  agent_id TEXT NOT NULL,
  status TEXT NOT NULL,
  body JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  agent_id TEXT NOT NULL,
  status TEXT NOT NULL,
  body JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policies (
  tenant_id TEXT PRIMARY KEY REFERENCES tenants(tenant_id),
  body JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_versions (
  id TEXT PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(tenant_id),
  version INTEGER NOT NULL,
  status TEXT NOT NULL,
  body JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL,
  approved_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS scopezero_state (
  id TEXT PRIMARY KEY,
  body JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scopezero_write_locks (
  id TEXT PRIMARY KEY,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS evidence_ledger (
  id TEXT PRIMARY KEY,
  time TIMESTAMPTZ NOT NULL,
  tenant_id TEXT,
  event_type TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  hash TEXT NOT NULL,
  record JSONB NOT NULL
);

CREATE INDEX IF NOT EXISTS evidence_ledger_tenant_time_idx ON evidence_ledger (tenant_id, time DESC);
CREATE INDEX IF NOT EXISTS missions_tenant_agent_idx ON missions (tenant_id, agent_id);
CREATE INDEX IF NOT EXISTS approvals_tenant_status_idx ON approvals (tenant_id, status);
CREATE INDEX IF NOT EXISTS policy_versions_tenant_version_idx ON policy_versions (tenant_id, version DESC);
