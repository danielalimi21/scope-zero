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

ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;
ALTER TABLE missions ENABLE ROW LEVEL SECURITY;
ALTER TABLE missions FORCE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE policies FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE evidence_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_ledger FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenants_scopezero_tenant_isolation ON tenants;
CREATE POLICY tenants_scopezero_tenant_isolation ON tenants
  USING (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*')
  WITH CHECK (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*');

DROP POLICY IF EXISTS agents_scopezero_tenant_isolation ON agents;
CREATE POLICY agents_scopezero_tenant_isolation ON agents
  USING (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*')
  WITH CHECK (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*');

DROP POLICY IF EXISTS missions_scopezero_tenant_isolation ON missions;
CREATE POLICY missions_scopezero_tenant_isolation ON missions
  USING (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*')
  WITH CHECK (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*');

DROP POLICY IF EXISTS approvals_scopezero_tenant_isolation ON approvals;
CREATE POLICY approvals_scopezero_tenant_isolation ON approvals
  USING (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*')
  WITH CHECK (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*');

DROP POLICY IF EXISTS policies_scopezero_tenant_isolation ON policies;
CREATE POLICY policies_scopezero_tenant_isolation ON policies
  USING (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*')
  WITH CHECK (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*');

DROP POLICY IF EXISTS policy_versions_scopezero_tenant_isolation ON policy_versions;
CREATE POLICY policy_versions_scopezero_tenant_isolation ON policy_versions
  USING (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*')
  WITH CHECK (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*');

DROP POLICY IF EXISTS evidence_ledger_scopezero_tenant_isolation ON evidence_ledger;
CREATE POLICY evidence_ledger_scopezero_tenant_isolation ON evidence_ledger
  USING (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*' OR tenant_id IS NULL)
  WITH CHECK (tenant_id = current_setting('scopezero.tenant_id', true) OR current_setting('scopezero.tenant_id', true) = '*' OR tenant_id IS NULL);
