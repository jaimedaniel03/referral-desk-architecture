# Architecture

```
listing signal
  → scheduled scan (pg_cron)         sql/functions_triggers.sql, scan_runs job state
  → normalization
  → duplicate detection              src/lib/dedupDecision.ts  (+ its test)
  → qualification & scoring
  → producer routing / ownership     sql/rls_policies.sql (agents_update policy)
  → compliance gate                  trg_enforce_outbound  (sql/functions_triggers.sql)
  → human review                     outreach requires stage approved_for_email
  → outreach (email via provider)
  → delivery webhooks                excerpts/webhook_resend_route.ts  (svix-verified)
  → append-only outreach log         outreach_limited_update trigger
  → relationship state               after_outreach_insert trigger updates stage/counters
  → policy attribution
```

Design notes:

- **Postgres is the queue** at pilot scale. Scheduled work runs on pg_cron
  (hourly follow-up marking, daily priority refresh, daily operational
  notifications); job state lives in tables (`scan_runs.status`,
  notification `email_attempts` / `email_failed_at`), so failures are
  visible rows, not lost messages.
- **Retries with a recorded reason.** A notification that keeps failing is
  abandoned with its reason and leaves the queue — one dead address cannot
  wedge the backlog. `emailed_at` means *provider accepted*, nothing else
  (that distinction exists because an outage once recorded people as
  notified; see the homepage failures section).
- **Human-in-the-loop on purpose.** Marketing email requires an explicitly
  approved template version and an agent at `approved_for_email`. The
  system makes the motion scalable; it does not remove judgment.
