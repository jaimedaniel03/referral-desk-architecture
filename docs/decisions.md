# Decisions, and what was deliberately not built

- **Postgres instead of a dedicated queue.** Pilot volume did not justify the
  operational cost of Kafka/Redis. pg_cron + job-state tables give visible,
  recoverable work at this scale; the tradeoff is re-evaluated at multi-tenant
  scale, not before.
- **RLS instead of application-only authorization.** Multi-tenancy must hold
  even when application code is wrong. The dedup bug in this repo is the
  proof: app-layer logic silently trusted an RLS-filtered read.
- **Scheduled scans, not real-time.** The business signal (new listings) does
  not change minute-to-minute; a cron cadence covers it without streaming
  infrastructure.
- **Human approval before outreach.** A bad automated message to a realtor
  costs more than a slower correct one. The database enforces the floor
  (suppression, caps, approved templates); a person makes the call.
- **Sending shipped disabled.** Outbound marketing stays off until the
  compliance sign-off completes — enforced by a database setting the send
  gate checks, not by a checklist.
- **No CRM sync yet.** At one agency, the system of record can be the system
  itself. Mapping to Salesforce/HubSpot objects is designed but unbuilt —
  building it before a second tenant would be resume-driven engineering.

This architecture is not what 1,000 agencies would need, and it is not
pretending to be. It is what one agency's pilot needed, built so the parts
that must never fail — isolation, suppression, auditability — cannot be
bypassed from above.
