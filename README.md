# Referral Desk — engineering proof layer

Sanitized artifacts from **Referral Desk**, a compliance-first referral pipeline for an
insurance agency: real-estate signals in, qualified/routed opportunities out, with the
database constraints documented in the SQL excerpts.

The production repository is private (it runs on a live agency's encrypted client data).
This repo exists so an engineer can inspect real implementation instead of taking a
portfolio's word for it. Everything here is copied from the production codebase with
nothing rewritten for show; the only edits are noted inline.

Full context: https://danielgonzalez.co/referral-desk

## What is runnable

```
npm ci && npm test        # 14 tests, also run in CI on every push
```

- `src/lib/webhookAuth.ts` — timing-safe secret verification for cron + webhook routes
  (header-only, fail-closed 503 when unconfigured)
- `src/lib/dedupDecision.ts` — duplicate detection that works **across** RLS visibility;
  its test file documents the real bug that motivated it
- `tests/` — the production test files for both, verbatim

## Read-only production artifacts

- `sql/functions_triggers.sql` — the pre-send compliance gate (`trg_enforce_outbound`):
  suppression list, opt-out/DNC, template approval, ONE-initial + ONE-follow-up
  sequence cap — all raised as Postgres exceptions before a row exists.
  Also the `outreach_events` triggers that restrict content updates and DELETE for the covered roles. Privileged administrators can change database definitions and grants.
- `sql/rls_policies.sql` — the row-level-security layer.
- `sql/pgtap_compliance.test.sql` — compliance invariants tested *inside* Postgres.
- `sql/postmortem_login_guard.sql` — a real incident, documented in the migration that
  fixed it: the brute-force login guard revoked EXECUTE from every role and granted it
  back to none, so it silently never ran.
- `excerpts/webhook_resend_route.ts` — svix signature verification, raw body first,
  401 on invalid (this closed a HIGH finding from a security review).
- `excerpts/twoTenantWrites.test.ts` — what breaks the day a second tenant goes live,
  written up as a test.
- `excerpts/sequenceRules_cap.excerpt.ts` — the sequence-cap unit tests.

## Docs

- [docs/architecture.md](docs/architecture.md) — the pipeline, stage by stage
- [docs/security.md](docs/security.md) — tenant isolation model + attack scenario
- [docs/decisions.md](docs/decisions.md) — decisions and deliberate restraint

## Evidence scope and reproducibility

The public command runs **14 tests for two helper modules**: header-secret authentication and duplicate decisions. The SQL and route files are read-only excerpts. This command does not execute pgTAP, the two-tenant integration excerpt, the production application, or provider-signature verification.

The portfolio reported **1,666 private checks on 2026-08-30**. That figure is a separate owner-reported production-suite claim. A current private run and its deployment gate are not established by a green result in this repository. Request a dated, revision-linked private run summary for that evidence.

From a clean checkout, use Node 22, then `npm ci` and `npm test`. The lockfile is committed; installed dependencies are ignored. CI uses the same install command.

This is a sanitized engineering artifact repository for a pilot. Its excerpts illustrate specified mechanisms, not a current production security certification. In particular, row-security policies depend on roles and grants, and privileged database administration is a separate boundary.
