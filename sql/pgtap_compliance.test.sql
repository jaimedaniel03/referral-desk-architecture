-- ═══════════════════════════════════════════════════════════════════════════
-- Referral Desk — pgTAP proof that compliance is enforced AT THE DATABASE.
-- Run with: supabase test db
--
-- Everything here executes as the table owner (postgres) — deliberately.
-- These rules are triggers and revoked privileges, not RLS policies, so even
-- the most privileged application path cannot bypass them. (DoD #2/#6/#7/#8)
-- ═══════════════════════════════════════════════════════════════════════════

begin;
create extension if not exists pgtap with schema extensions;

select plan(33);

-- ─────────────────────────────────────────────────────────────────────────────
-- 1. Suppression list: PERMANENT and append-only (DoD #7)
-- ─────────────────────────────────────────────────────────────────────────────

select lives_ok(
  $$ insert into suppression_list (email, suppression_type, method)
     values ('t-suppress@pgtap.test', 'email_unsubscribe', 'pgtap fixture') $$,
  'suppression_list accepts INSERT'
);

select throws_ok(
  $$ update suppression_list set note = 'rewrite history' where email = 't-suppress@pgtap.test' $$,
  'suppression_list is append-only: UPDATE is not permitted'
);

select throws_ok(
  $$ delete from suppression_list where email = 't-suppress@pgtap.test' $$,
  'suppression_list is append-only: DELETE is not permitted'
);

select throws_ok(
  'truncate table suppression_list',
  'suppression_list is append-only: TRUNCATE is not permitted'
);

select ok(
  not has_table_privilege('authenticated', 'suppression_list', 'DELETE'),
  'authenticated role holds no DELETE privilege on suppression_list'
);

select ok(
  not has_table_privilege('service_role', 'suppression_list', 'DELETE'),
  'even service_role holds no DELETE privilege on suppression_list'
);

select ok(
  not has_table_privilege('authenticated', 'suppression_list', 'UPDATE'),
  'authenticated role holds no UPDATE privilege on suppression_list'
);

-- ─────────────────────────────────────────────────────────────────────────────
-- 2. Agents: lead_source is mandatory and enumerated (Part 1 #2)
-- ─────────────────────────────────────────────────────────────────────────────

select throws_ok(
  $$ insert into agents (first_name, last_name, business_email)
     values ('No', 'Source', 't0@pgtap.test') $$,
  '23502'
);

select throws_ok(
  $$ insert into agents (first_name, last_name, business_email, lead_source)
     values ('Bought', 'List', 't0b@pgtap.test', 'purchased_database') $$,
  '23514'
);

select lives_ok(
  $$ insert into agents (first_name, last_name, business_email, lead_source, lead_source_doc)
     values ('Bought', 'Documented', 't0c@pgtap.test', 'purchased_database',
             'License agreement #2026-004 on file; commercial use permitted.') $$,
  'purchased_database is accepted once the rights reference is documented'
);

-- ─────────────────────────────────────────────────────────────────────────────
-- 3. Opt-out reactivation requires a durable consent record (Part 1 #6)
-- ─────────────────────────────────────────────────────────────────────────────

insert into agents (first_name, last_name, business_email, lead_source, opted_out, opted_out_at)
values ('Opted', 'Out', 't1@pgtap.test', 'manual_research', true, now() - interval '1 day');

select throws_ok(
  $$ update agents set opted_out = false where business_email = 't1@pgtap.test' $$,
  'cannot clear opt-out: no reactivation consent record on file (who/when/how/language required)'
);

insert into consent_records (agent_id, channel, granted_by, method, language, occurred_at)
select id, 'reactivation', 'T1 Agent (self, by phone)', 'phone call',
       'Please resume contacting me about insurance resources for my clients.', now()
from agents where business_email = 't1@pgtap.test';

select lives_ok(
  $$ update agents set opted_out = false where business_email = 't1@pgtap.test' $$,
  'opt-out clears only after a reactivation consent record exists'
);

-- ─────────────────────────────────────────────────────────────────────────────
-- 4. Stage gates: verification before approval
-- ─────────────────────────────────────────────────────────────────────────────

insert into agents (first_name, last_name, business_email, lead_source)
values ('Stage', 'Walker', 't2@pgtap.test', 'networking_event');

select throws_ok(
  $$ update agents set stage = 'approved_for_email' where business_email = 't2@pgtap.test' $$,
  'approved_for_email can only be entered from data_verified'
);

select lives_ok(
  $$ update agents set stage = 'data_verified' where business_email = 't2@pgtap.test' $$,
  'new_lead -> data_verified is permitted'
);

select lives_ok(
  $$ update agents set stage = 'approved_for_email' where business_email = 't2@pgtap.test' $$,
  'data_verified -> approved_for_email is permitted'
);

-- ─────────────────────────────────────────────────────────────────────────────
-- 5. Outbound send rules on the append-only outreach log
-- ─────────────────────────────────────────────────────────────────────────────

update system_settings
set sending_enabled = true, campaigns_paused = false, sms_feature_enabled = false
where id = 1;

select lives_ok(
  $$ insert into outreach_events
       (agent_id, channel, direction, template_id, template_version, template_kind,
        subject, body, to_identity, delivery_status)
     select a.id, 'email', 'outbound', t.id, t.version, 'initial_email',
            'pgtap initial', 'pgtap body', a.business_email, 'sent'
     from agents a, templates t
     where a.business_email = 't2@pgtap.test'
       and t.kind = 'initial_email' and t.status = 'approved' $$,
  'a compliant initial email insert is accepted'
);

select is(
  (select stage::text from agents where business_email = 't2@pgtap.test'),
  'initial_email_sent',
  'a marketing send auto-advances approved_for_email -> initial_email_sent'
);

select throws_ok(
  $$ insert into outreach_events
       (agent_id, channel, direction, template_id, template_version, template_kind,
        subject, body, to_identity, delivery_status)
     select a.id, 'email', 'outbound', t.id, t.version, 'initial_email',
            'pgtap initial again', 'pgtap body', a.business_email, 'sent'
     from agents a, templates t
     where a.business_email = 't2@pgtap.test'
       and t.kind = 'initial_email' and t.status = 'approved' $$,
  'send blocked: the initial email was already sent once to this contact'
);

select lives_ok(
  $$ insert into outreach_events
       (agent_id, channel, direction, template_id, template_version, template_kind,
        subject, body, to_identity, delivery_status)
     select a.id, 'email', 'outbound', t.id, t.version, 'follow_up_email',
            'pgtap follow-up', 'pgtap body', a.business_email, 'sent'
     from agents a, templates t
     where a.business_email = 't2@pgtap.test'
       and t.kind = 'follow_up_email' and t.status = 'approved' $$,
  'the single permitted follow-up is accepted'
);

select throws_ok(
  $$ insert into outreach_events
       (agent_id, channel, direction, template_id, template_version, template_kind,
        subject, body, to_identity, delivery_status)
     select a.id, 'email', 'outbound', t.id, t.version, 'follow_up_email',
            'pgtap follow-up 2', 'pgtap body', a.business_email, 'sent'
     from agents a, templates t
     where a.business_email = 't2@pgtap.test'
       and t.kind = 'follow_up_email' and t.status = 'approved' $$,
  'send blocked: the single permitted follow-up was already sent; the sequence has ended permanently'
);

-- Suppressed recipient: marketing insert is impossible.
insert into agents (first_name, last_name, business_email, lead_source)
values ('Sup', 'Pressed', 't3@pgtap.test', 'manual_research');
update agents set stage = 'data_verified'      where business_email = 't3@pgtap.test';
update agents set stage = 'approved_for_email' where business_email = 't3@pgtap.test';
insert into suppression_list (email, agent_id, suppression_type, method)
select business_email, id, 'email_unsubscribe', 'pgtap fixture'
from agents where business_email = 't3@pgtap.test';

select throws_ok(
  $$ insert into outreach_events
       (agent_id, channel, direction, template_id, template_version, template_kind,
        subject, body, to_identity, delivery_status)
     select a.id, 'email', 'outbound', t.id, t.version, 'initial_email',
            'pgtap suppressed', 'pgtap body', a.business_email, 'sent'
     from agents a, templates t
     where a.business_email = 't3@pgtap.test'
       and t.kind = 'initial_email' and t.status = 'approved' $$,
  'send blocked: recipient is on the suppression list'
);

-- Kill switch (DoD #9) and ships-disabled default (DoD #13), server-side.
insert into agents (first_name, last_name, business_email, lead_source)
values ('Kill', 'Switch', 't4@pgtap.test', 'networking_event');
update agents set stage = 'data_verified'      where business_email = 't4@pgtap.test';
update agents set stage = 'approved_for_email' where business_email = 't4@pgtap.test';

update system_settings set campaigns_paused = true where id = 1;

select throws_ok(
  $$ insert into outreach_events
       (agent_id, channel, direction, template_id, template_version, template_kind,
        subject, body, to_identity, delivery_status)
     select a.id, 'email', 'outbound', t.id, t.version, 'initial_email',
            'pgtap paused', 'pgtap body', a.business_email, 'sent'
     from agents a, templates t
     where a.business_email = 't4@pgtap.test'
       and t.kind = 'initial_email' and t.status = 'approved' $$,
  'send blocked: campaigns are paused (kill switch active)'
);

update system_settings set campaigns_paused = false, sending_enabled = false where id = 1;

select throws_ok(
  $$ insert into outreach_events
       (agent_id, channel, direction, template_id, template_version, template_kind,
        subject, body, to_identity, delivery_status)
     select a.id, 'email', 'outbound', t.id, t.version, 'initial_email',
            'pgtap disabled', 'pgtap body', a.business_email, 'sent'
     from agents a, templates t
     where a.business_email = 't4@pgtap.test'
       and t.kind = 'initial_email' and t.status = 'approved' $$,
  'send blocked: sending is disabled until the launch checklist (incl. attorney/compliance sign-off) is completed'
);

-- ─────────────────────────────────────────────────────────────────────────────
-- 6. SMS hard gate (Part 1 #3): feature flag + recorded consent + STOP language
-- ─────────────────────────────────────────────────────────────────────────────

insert into agents (first_name, last_name, business_email, business_phone, lead_source)
values ('Sms', 'Gate', 't5@pgtap.test', '650-555-0155', 'networking_event');

-- The global send freeze covers SMS too (2026-08-24 audit #2). While
-- sending_enabled is false (still off from the disabled-email test above), an
-- SMS is stopped by the system-wide freeze BEFORE any SMS-specific gate is
-- reached — the freeze is not marketing-email-only.
select throws_ok(
  $$ insert into outreach_events (agent_id, channel, direction, template_kind, body, to_identity, delivery_status)
     select id, 'sms', 'outbound', 'sms',
            'pgtap sms. Reply STOP to opt out.', business_phone, 'sent'
     from agents where business_email = 't5@pgtap.test' $$,
  'send blocked: sending is disabled until the launch checklist (incl. attorney/compliance sign-off) is completed'
);

-- Lift only the system-wide freeze, to exercise the SMS-specific gates in
-- isolation. (sms_feature_enabled is still off from the section-5 setup.)
update system_settings set sending_enabled = true where id = 1;

select throws_ok(
  $$ insert into outreach_events (agent_id, channel, direction, template_kind, body, to_identity, delivery_status)
     select id, 'sms', 'outbound', 'sms',
            'pgtap sms. Reply STOP to opt out.', business_phone, 'sent'
     from agents where business_email = 't5@pgtap.test' $$,
  'SMS is disabled system-wide (admin feature flag is off)'
);

update system_settings set sms_feature_enabled = true where id = 1;

select throws_ok(
  $$ insert into outreach_events (agent_id, channel, direction, template_kind, body, to_identity, delivery_status)
     select id, 'sms', 'outbound', 'sms',
            'pgtap sms. Reply STOP to opt out.', business_phone, 'sent'
     from agents where business_email = 't5@pgtap.test' $$,
  'SMS blocked: no recorded SMS consent (source/date/language) or management-and-counsel approval note'
);

update agents
set sms_consent = 'granted',
    sms_consent_source = 'phone call with agent',
    sms_consent_date = now(),
    sms_consent_language = 'Yes, you can text me at this number about insurance for my clients.'
where business_email = 't5@pgtap.test';

select lives_ok(
  $$ insert into outreach_events (agent_id, channel, direction, template_kind, body, to_identity, delivery_status)
     select id, 'sms', 'outbound', 'sms',
            'pgtap sms with consent. Reply STOP to opt out.', business_phone, 'sent'
     from agents where business_email = 't5@pgtap.test' $$,
  'SMS with recorded consent and STOP language is accepted'
);

select throws_ok(
  $$ insert into outreach_events (agent_id, channel, direction, template_kind, body, to_identity, delivery_status)
     select id, 'sms', 'outbound', 'sms',
            'pgtap sms missing the required opt-out word', business_phone, 'sent'
     from agents where business_email = 't5@pgtap.test' $$,
  'SMS blocked: message must contain the STOP opt-out instruction'
);

-- ─────────────────────────────────────────────────────────────────────────────
-- 7. Outreach log: append-only, content immutable, status updatable
-- ─────────────────────────────────────────────────────────────────────────────

select throws_ok(
  $$ update outreach_events set body = 'tampered'
     where to_identity = 't2@pgtap.test' and template_kind = 'initial_email' $$,
  'outreach_events content is immutable; only delivery_status, call_outcome, provider_message_id and meta may change'
);

select throws_ok(
  $$ delete from outreach_events where to_identity = 't2@pgtap.test' $$,
  'outreach_events is append-only: DELETE is not permitted'
);

select lives_ok(
  $$ update outreach_events set delivery_status = 'delivered'
     where to_identity = 't2@pgtap.test' and template_kind = 'initial_email' $$,
  'delivery_status alone may be updated (webhook status ingestion)'
);

-- ─────────────────────────────────────────────────────────────────────────────
-- 8. Referrals never become marketing without separate client consent
-- ─────────────────────────────────────────────────────────────────────────────

insert into referrals (agent_id, client_name, property_address,
                       permission_scope, permission_granted_by, permission_granted_at)
select id, 'PgTap Client (fictional)', '1 Test Way, San Mateo, CA',
       'Quote homeowners insurance for 1 Test Way only',
       'PgTap Client, verbally via their agent', now()
from agents where business_email = 't2@pgtap.test';

select throws_ok(
  $$ update referrals set marketing_consent = true
     where client_name = 'PgTap Client (fictional)' $$,
  'client marketing requires a separate recorded consent (who/when/how/language) — a referral never enrolls the client in marketing'
);

insert into consent_records (referral_id, channel, granted_by, method, language, occurred_at)
select id, 'client_marketing', 'PgTap Client', 'email confirmation',
       'Yes, you may send me occasional insurance updates from your office.', now()
from referrals where client_name = 'PgTap Client (fictional)';

select lives_ok(
  $$ update referrals set marketing_consent = true
     where client_name = 'PgTap Client (fictional)' $$,
  'marketing_consent flips only after a client_marketing consent record exists'
);

select * from finish();
rollback;
