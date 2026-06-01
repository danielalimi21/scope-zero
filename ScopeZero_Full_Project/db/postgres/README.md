# Postgres Migration Path

The local ScopeZero build uses SQLite so it can run without installing dependencies.

For an enterprise pilot or production-style deployment, run the state store on managed Postgres using:

```bash
SCOPEZERO_STORE=postgres
DATABASE_URL=postgres://...
```

`src/postgresStore.js` provides the application adapter for shared state writes. `schema.sql` documents the target database shape, including the state document, tenant-scoped relational mirrors, policy version table, evidence ledger table, and write-lock table.

Tenant-scoped tables use Postgres row-level security. The application sets the session variable `scopezero.tenant_id` before tenant-scoped relational access:

```sql
SET LOCAL scopezero.tenant_id = 'tenant_contoso';
```

The service maintenance path uses `scopezero.tenant_id = '*'` while mirroring the signed state document into relational tables. Do not grant customer-facing roles direct access to `scopezero_state`; use the RLS-protected relational tables or tenant-filtered API responses.

The local evidence ledger still writes JSONL by default. For production SaaS, mirror or replace the JSONL ledger with the `evidence_ledger` table or append-only object storage.

Recommended production settings:

- managed Postgres with point-in-time recovery
- encrypted storage
- private networking
- connection pooling
- row-level security by `tenant_id`
- daily logical backups
- migration tool such as Flyway, Liquibase, Prisma Migrate, or Sqitch
- append-only ledger retention or immutable object storage
