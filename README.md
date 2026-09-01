# Referral Desk — engineering proof layer

Sanitized artifacts from **Referral Desk**, a compliance-first referral pipeline for an
insurance agency: real-estate signals in, qualified/routed opportunities out, with the
compliance rules enforced by Postgres rather than by application code or rep behaviour.

The production repository is private (it runs on a live agency's encrypted client data).
This repo exists so an engineer can inspect real implementation instead of taking a
portfolio's word for it. Everything here is copied from the production codebase with
nothing rewritten for show; the only edits are noted inline.

Full context: https://danielgonzalez.co/referral-desk

## What is runnable

```
npm install && npm test        # 14 tests, also run in CI on every push
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
  Also the append-only `outreach_events` triggers: content is immutable, DELETE never.
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

## Scale disclosure

Referral Desk is a **pilot** at one agency. The production suite behind the private
repo is 1,666 checks across 92 unit / 37 integration / 3 e2e files plus pgTAP; deploys
fail closed when a security or compliance test breaks. Numbers here are chosen to be
verifiable, not impressive.
