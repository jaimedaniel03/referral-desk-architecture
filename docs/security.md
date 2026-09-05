# Security & tenant isolation

## Model

Every tenant-bound table carries an organization identifier, and RLS policies
gate access below the application layer (`sql/rls_policies.sql`). Compliance
invariants — suppression, opt-out, sequence caps, template approval — are
`BEFORE INSERT` triggers on `outreach_events` constrain the covered insert paths.
The excerpts also restrict content updates and DELETE for the documented roles.
Database owners and privileged administrators can change policies, triggers, and grants;
RLS exemptions and SECURITY DEFINER operations require separate review.

## Attack scenario

A producer from Agency A calls the API directly with an Agency B record id.

Expected: the read comes back empty / the write raises — RLS filters rows the
caller cannot see, and writes carry the caller's tenant.

Related artifacts (scope matters):
- `excerpts/twoTenantWrites.test.ts` — session-less writes (cron, webhooks,
  unsubscribe) must state their tenant explicitly. This is a read-only integration excerpt, not run by public CI.
- `src/lib/dedupDecision.ts` + test — a duplicate check that used the
  caller's own RLS-filtered read once reported "no duplicate" about a record
  it structurally could not see, then inserted. The rewrite classifies
  matches *across* visibility and blocks with 409; the test reconstructs the
  original failing inputs.
- `sql/pgtap_compliance.test.sql` — database assertions supplied for inspection, not executed by the public test command.

## Webhooks

`excerpts/webhook_resend_route.ts`: raw body read first, svix signature
verified, invalid → 401. Cron and inbound routes use header-only, timing-safe
secrets that fail closed (503) when unconfigured (`src/lib/webhookAuth.ts`) —
a query-string secret is rejected by test.

The 14 public tests cover header-secret authentication and duplicate-decision helpers. A provider-signature rejection test, tenant database setup, and deployed-role checks are not part of this runnable subset.
