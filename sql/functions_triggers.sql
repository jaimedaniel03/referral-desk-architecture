-- ═══════════════════════════════════════════════════════════════════════════
-- Referral Desk — functions and triggers: the database-level compliance engine
-- The rules here are IMPOSSIBILITIES, not policies. UI and API checks are
-- convenience layers; these triggers are the enforcement.
-- ═══════════════════════════════════════════════════════════════════════════

-- ── Generic helpers ─────────────────────────────────────────────────────────

create or replace function touch_updated_at() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end $$;

create trigger trg_touch_profiles        before update on profiles        for each row execute function touch_updated_at();
create trigger trg_touch_settings        before update on system_settings for each row execute function touch_updated_at();
create trigger trg_touch_agents          before update on agents          for each row execute function touch_updated_at();
create trigger trg_touch_listings        before update on listings        for each row execute function touch_updated_at();
create trigger trg_touch_templates       before update on templates       for each row execute function touch_updated_at();
create trigger trg_touch_campaigns       before update on campaigns       for each row execute function touch_updated_at();
create trigger trg_touch_referrals       before update on referrals       for each row execute function touch_updated_at();
create trigger trg_touch_tasks           before update on tasks           for each row execute function touch_updated_at();

-- Append-only guard. Attached to tables that can never be edited or purged.
create or replace function forbid_change() returns trigger
language plpgsql as $$
begin
  raise exception '% is append-only: % is not permitted', tg_table_name, tg_op
    using errcode = 'P0001';
end $$;

-- Suppression list: permanent. No UPDATE, no DELETE — ever. (DoD #7)
create trigger trg_suppression_immutable
  before update or delete on suppression_list
  for each row execute function forbid_change();

-- TRUNCATE bypasses row triggers; block it with a statement-level trigger.
create trigger trg_suppression_no_truncate
  before truncate on suppression_list
  for each statement execute function forbid_change();

create trigger trg_audit_immutable
  before update or delete on audit_log
  for each row execute function forbid_change();
create trigger trg_audit_no_truncate
  before truncate on audit_log
  for each statement execute function forbid_change();

create trigger trg_consent_immutable
  before update or delete on consent_records
  for each row execute function forbid_change();

create trigger trg_email_events_immutable
  before update or delete on email_events
  for each row execute function forbid_change();

-- Outreach events: content is immutable once written; only delivery_status
-- and meta may be updated (webhook status ingestion). DELETE is never allowed.
create or replace function outreach_limited_update() returns trigger
language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'outreach_events is append-only: DELETE is not permitted';
  end if;
  if new.id            is distinct from old.id
    or new.agent_id      is distinct from old.agent_id
    or new.referral_id   is distinct from old.referral_id
    or new.campaign_id   is distinct from old.campaign_id
    or new.channel       is distinct from old.channel
    or new.direction     is distinct from old.direction
    or new.template_id   is distinct from old.template_id
    or new.template_version is distinct from old.template_version
    or new.template_kind is distinct from old.template_kind
    or new.subject       is distinct from old.subject
    or new.body          is distinct from old.body
    or new.from_identity is distinct from old.from_identity
    or new.to_identity   is distinct from old.to_identity
    or new.sent_by       is distinct from old.sent_by
    or new.occurred_at   is distinct from old.occurred_at
    or new.created_at    is distinct from old.created_at
  then
    raise exception 'outreach_events content is immutable; only delivery_status, call_outcome, provider_message_id and meta may change';
  end if;
  return new;
end $$;

create trigger trg_outreach_limited_update
  before update or delete on outreach_events
  for each row execute function outreach_limited_update();

-- ── Auth / roles ────────────────────────────────────────────────────────────

create or replace function is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from profiles
    where id = auth.uid() and role = 'admin' and is_active
  );
$$;

-- New auth user → profile row. First user bootstraps as admin (documented in README).
create or replace function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_role user_role := 'producer';
begin
  if not exists (select 1 from profiles) then
    v_role := 'admin';
  end if;
  insert into profiles (id, email, full_name, role)
  values (new.id, new.email, coalesce(new.raw_user_meta_data ->> 'full_name', ''), v_role)
  on conflict (id) do nothing;
  return new;
end $$;

create trigger trg_on_auth_user_created
  after insert on auth.users
  for each row execute function handle_new_user();

-- ── Audit ───────────────────────────────────────────────────────────────────

create or replace function log_audit(
  p_action text, p_entity_type text, p_entity_id text, p_diff jsonb default null
) returns void
language plpgsql security definer set search_path = public as $$
begin
  insert into audit_log (actor, actor_email, action, entity_type, entity_id, diff)
  values (
    auth.uid(),
    coalesce(nullif(current_setting('request.jwt.claims', true), '')::jsonb ->> 'email', 'system'),
    p_action, p_entity_type, p_entity_id, p_diff
  );
end $$;

-- Row-change auditing for sensitive tables: records only the changed columns.
create or replace function audit_row_change() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_old jsonb := to_jsonb(old);
  v_new jsonb := to_jsonb(new);
  v_changed jsonb := '{}'::jsonb;
  k text;
begin
  for k in select jsonb_object_keys(v_new) loop
    if v_new -> k is distinct from v_old -> k then
      v_changed := v_changed || jsonb_build_object(k, jsonb_build_object('old', v_old -> k, 'new', v_new -> k));
    end if;
  end loop;
  if v_changed <> '{}'::jsonb then
    perform log_audit('update', tg_table_name, (v_new ->> 'id'), v_changed);
  end if;
  return new;
end $$;

create trigger trg_audit_agents    after update on agents          for each row execute function audit_row_change();
create trigger trg_audit_referrals after update on referrals       for each row execute function audit_row_change();
create trigger trg_audit_templates after update on templates       for each row execute function audit_row_change();
create trigger trg_audit_campaigns after update on campaigns       for each row execute function audit_row_change();
create trigger trg_audit_settings  after update on system_settings for each row execute function audit_row_change();

-- ── Suppression checks ──────────────────────────────────────────────────────

create or replace function norm_phone(p text) returns text
language sql immutable as $$
  select nullif(right(regexp_replace(coalesce(p, ''), '\D', '', 'g'), 10), '');
$$;

create or replace function is_email_suppressed(p_email text) returns boolean
language sql stable security definer set search_path = public as $$
  select p_email is not null and exists (
    select 1 from suppression_list where email is not null and lower(email::text) = lower(p_email)
  );
$$;

create or replace function is_phone_suppressed(p_phone text) returns boolean
language sql stable security definer set search_path = public as $$
  select norm_phone(p_phone) is not null and exists (
    select 1 from suppression_list
    where phone is not null and norm_phone(phone) = norm_phone(p_phone)
  );
$$;

-- ── Business days ───────────────────────────────────────────────────────────

create or replace function add_business_days(d date, n int) returns date
language plpgsql immutable as $$
declare
  result date := d;
  added int := 0;
begin
  while added < n loop
    result := result + 1;
    if extract(isodow from result) < 6 then
      added := added + 1;
    end if;
  end loop;
  return result;
end $$;

-- ── Agent guards (Part 1 #6, Part 5 gates) ─────────────────────────────────
-- Opted-out / do-not-contact contacts can NEVER be re-activated without a
-- new reactivation consent record documenting who / when / how / language.
create or replace function enforce_agent_guards() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  -- Track when the stage last changed (used by terminal-stage guard).
  if new.stage is distinct from old.stage then
    new.stage_changed_at := now();
  end if;

  -- Clearing opted_out requires a reactivation consent recorded at/after the opt-out.
  if old.opted_out and not new.opted_out then
    if not exists (
      select 1 from consent_records c
      where c.agent_id = old.id
        and c.channel = 'reactivation'
        and c.occurred_at >= coalesce(old.opted_out_at, '-infinity'::timestamptz)
    ) then
      raise exception 'cannot clear opt-out: no reactivation consent record on file (who/when/how/language required)';
    end if;
  end if;
  if new.opted_out and not old.opted_out then
    new.opted_out_at := coalesce(new.opted_out_at, now());
  end if;

  -- Same guard for the do-not-contact flag.
  if old.do_not_contact and not new.do_not_contact then
    if not exists (
      select 1 from consent_records c
      where c.agent_id = old.id
        and c.channel = 'reactivation'
        and c.occurred_at >= coalesce(old.do_not_contact_at, '-infinity'::timestamptz)
    ) then
      raise exception 'cannot clear do-not-contact: no reactivation consent record on file';
    end if;
  end if;
  if new.do_not_contact and not old.do_not_contact then
    new.do_not_contact_at := coalesce(new.do_not_contact_at, now());
  end if;

  -- Leaving a marketing-terminal stage requires the same reactivation consent.
  if old.stage in ('do_not_contact', 'not_interested') and new.stage is distinct from old.stage then
    if not exists (
      select 1 from consent_records c
      where c.agent_id = old.id
        and c.channel = 'reactivation'
        and c.occurred_at >= old.stage_changed_at
    ) then
      raise exception 'stage % is terminal for marketing: leaving it requires a reactivation consent record', old.stage;
    end if;
  end if;

  -- Forward gates: verification before approval, approval only from verified.
  if new.stage = 'data_verified' and old.stage not in ('new_lead', 'invalid_contact', 'data_verified') then
    raise exception 'data_verified can only be entered from new_lead or invalid_contact (re-verification)';
  end if;
  if new.stage = 'approved_for_email' and old.stage not in ('data_verified', 'approved_for_email') then
    raise exception 'approved_for_email can only be entered from data_verified';
  end if;

  -- SMS consent bookkeeping: granting consent requires source, date and language.
  if new.sms_consent = 'granted' and old.sms_consent is distinct from 'granted' then
    if new.sms_consent_source is null or new.sms_consent_date is null or new.sms_consent_language is null then
      raise exception 'sms consent requires source, date, and the captured consent language';
    end if;
  end if;

  return new;
end $$;

create trigger trg_agent_guards
  before update on agents
  for each row execute function enforce_agent_guards();

-- ── Outbound send rules (Parts 1 & 4, DoD #6/#7/#8) ─────────────────────────
-- Fires on EVERY insert into the append-only outreach log. Because every send
-- path must create this row, every send path inherits these checks.
create or replace function enforce_outbound_rules() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  v_agent agents%rowtype;
  v_settings system_settings%rowtype;
  v_template templates%rowtype;
  v_initials int;
  v_followups int;
begin
  if new.direction <> 'outbound' then
    return new;  -- inbound messages are always logged
  end if;

  select * into v_settings from system_settings where id = 1;

  if new.agent_id is not null then
    select * into v_agent from agents where id = new.agent_id;
  end if;

  -- ═ SMS: hard gate at the database level (Part 1 #3) ═
  if new.channel = 'sms' then
    if not v_settings.sms_feature_enabled then
      raise exception 'SMS is disabled system-wide (admin feature flag is off)';
    end if;
    if v_agent.id is null then
      raise exception 'SMS requires an agent record with recorded consent';
    end if;
    if is_phone_suppressed(v_agent.business_phone) then
      raise exception 'SMS blocked: number is on the suppression list';
    end if;
    if not (
      (v_agent.sms_consent = 'granted'
        and v_agent.sms_consent_source is not null
        and v_agent.sms_consent_date is not null
        and v_agent.sms_consent_language is not null)
      or (v_agent.sms_mgmt_counsel_note is not null and btrim(v_agent.sms_mgmt_counsel_note) <> '')
    ) then
      raise exception 'SMS blocked: no recorded SMS consent (source/date/language) or management-and-counsel approval note';
    end if;
    if position('STOP' in upper(new.body)) = 0 then
      raise exception 'SMS blocked: message must contain the STOP opt-out instruction';
    end if;
    if v_agent.opted_out or v_agent.do_not_contact or v_agent.outreach_paused then
      raise exception 'SMS blocked: contact is opted out, do-not-contact, or paused pending review';
    end if;
    return new;
  end if;

  -- ═ Phone: human call logging only; nothing to gate at insert time ═
  if new.channel = 'phone' then
    return new;
  end if;

  -- ═ Email ═
  if new.channel = 'email' then
    if v_agent.id is not null and is_email_suppressed(v_agent.business_email::text) then
      -- Suppression blocks ALL email, marketing and transactional alike,
      -- when the address itself was suppressed.
      raise exception 'send blocked: recipient is on the suppression list';
    end if;
    if new.to_identity is not null and is_email_suppressed(new.to_identity) then
      raise exception 'send blocked: recipient address is on the suppression list';
    end if;

    if new.template_kind in ('initial_email', 'listing_email', 'follow_up_email') then
      -- Marketing email rules.
      if v_agent.id is null then
        raise exception 'marketing email requires an agent record';
      end if;
      if v_agent.opted_out or v_agent.do_not_contact then
        raise exception 'send blocked: contact has opted out or is do-not-contact';
      end if;
      if v_agent.outreach_paused then
        raise exception 'send blocked: contact is paused pending human review of an inbound message';
      end if;
      if v_agent.stage in ('do_not_contact', 'not_interested', 'invalid_contact') then
        raise exception 'send blocked: stage % does not permit marketing email', v_agent.stage;
      end if;
      if not v_settings.sending_enabled then
        raise exception 'send blocked: sending is disabled until the launch checklist (incl. attorney/compliance sign-off) is completed';
      end if;
      if v_settings.campaigns_paused then
        raise exception 'send blocked: campaigns are paused (kill switch active)';
      end if;

      -- Template must be the approved version of its kind.
      if new.template_id is null then
        raise exception 'marketing email requires an approved template';
      end if;
      select * into v_template from templates where id = new.template_id;
      if v_template.status <> 'approved' then
        raise exception 'send blocked: template is not approved';
      end if;
      if v_template.kind <> new.template_kind or v_template.version is distinct from new.template_version then
        raise exception 'send blocked: template kind/version mismatch with the outreach record';
      end if;

      -- Sequence cap: ONE initial, at most ONE follow-up, then permanent stop.
      select
        count(*) filter (where template_kind in ('initial_email', 'listing_email')),
        count(*) filter (where template_kind = 'follow_up_email')
      into v_initials, v_followups
      from outreach_events
      where agent_id = new.agent_id and channel = 'email' and direction = 'outbound'
        and delivery_status <> 'failed';

      if new.template_kind in ('initial_email', 'listing_email') then
        if v_initials >= 1 then
          raise exception 'send blocked: the initial email was already sent once to this contact';
        end if;
        if v_agent.stage <> 'approved_for_email' then
          raise exception 'send blocked: initial email requires stage approved_for_email (currently %)', v_agent.stage;
        end if;
      end if;

      if new.template_kind = 'follow_up_email' then
        if v_initials = 0 then
          raise exception 'send blocked: no initial email on record; a follow-up cannot lead';
        end if;
        if v_followups >= 1 then
          raise exception 'send blocked: the single permitted follow-up was already sent; the sequence has ended permanently';
        end if;
        if v_agent.stage not in ('initial_email_sent', 'follow_up_due') then
          raise exception 'send blocked: follow-up requires stage initial_email_sent or follow_up_due (currently %)', v_agent.stage;
        end if;
      end if;

      -- Template B: must reference one of this agent's listings; the listing's
      -- authorized source is guaranteed NOT NULL by schema.
      if new.template_kind = 'listing_email' then
        if new.meta ->> 'listing_id' is null or not exists (
          select 1 from listings l
          where l.id = (new.meta ->> 'listing_id')::uuid
            and l.agent_id = new.agent_id
            and l.deleted_at is null
        ) then
          raise exception 'send blocked: listing email requires a linked listing (with recorded authorized source) belonging to this agent';
        end if;
      end if;
    elsif new.template_kind = 'transactional' then
      -- Operational service email. Allowed for opted-out contacts ONLY in the
      -- context of a referral they are a party to (they asked for the service).
      if v_agent.id is not null and (v_agent.opted_out or v_agent.do_not_contact) and new.referral_id is null then
        raise exception 'send blocked: transactional email to an opted-out contact requires a linked referral';
      end if;
    end if;
    return new;
  end if;

  return new;
end $$;

create trigger trg_enforce_outbound
  before insert on outreach_events
  for each row execute function enforce_outbound_rules();

-- After a send is logged, update the contact's counters and stage.
create or replace function after_outreach_insert() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.agent_id is not null and new.direction = 'outbound' then
    update agents set
      last_contact_at  = greatest(coalesce(last_contact_at, new.occurred_at), new.occurred_at),
      first_contact_at = coalesce(first_contact_at, new.occurred_at),
      contact_attempts = contact_attempts + 1,
      stage = case
        when new.template_kind in ('initial_email', 'listing_email') and stage = 'approved_for_email'
          then 'initial_email_sent'::relationship_stage
        else stage
      end
    where id = new.agent_id;
  end if;
  if new.agent_id is not null and new.direction = 'inbound' then
    update agents set last_contact_at = greatest(coalesce(last_contact_at, new.occurred_at), new.occurred_at)
    where id = new.agent_id;
  end if;
  return new;
end $$;

create trigger trg_after_outreach
  after insert on outreach_events
  for each row execute function after_outreach_insert();

-- ── Referral guards ─────────────────────────────────────────────────────────
-- A referral never enrolls the client in marketing. marketing_consent can only
-- flip true when a client_marketing consent record exists for this referral.
create or replace function enforce_referral_guards() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if new.marketing_consent and (tg_op = 'INSERT' or not old.marketing_consent) then
    if not exists (
      select 1 from consent_records c
      where c.referral_id = new.id and c.channel = 'client_marketing'
    ) then
      raise exception 'client marketing requires a separate recorded consent (who/when/how/language) — a referral never enrolls the client in marketing';
    end if;
  end if;
  return new;
end $$;

create trigger trg_referral_guards
  before insert or update on referrals
  for each row execute function enforce_referral_guards();

-- Templates: approved rows are immutable except retiring them.
create or replace function enforce_template_immutability() returns trigger
language plpgsql as $$
begin
  if old.status = 'approved' then
    if new.subject_template is distinct from old.subject_template
      or new.body_template is distinct from old.body_template
      or new.kind is distinct from old.kind
      or new.version is distinct from old.version then
      raise exception 'approved templates are immutable — create a new version instead';
    end if;
    if new.status not in ('approved', 'retired') then
      raise exception 'an approved template can only be retired';
    end if;
  end if;
  return new;
end $$;

create trigger trg_template_immutable
  before update on templates
  for each row execute function enforce_template_immutability();

-- ── Kill switch (Part 5) ────────────────────────────────────────────────────
-- ANY employee can pause instantly. Only an Admin can resume.
create or replace function pause_all_campaigns() returns void
language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then
    raise exception 'authentication required';
  end if;
  update system_settings
  set campaigns_paused = true, paused_by = auth.uid(), paused_at = now()
  where id = 1;
  update campaigns set status = 'paused' where status = 'approved';
  perform log_audit('pause_all_campaigns', 'system_settings', '1', null);
end $$;

create or replace function resume_campaigns() returns void
language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then
    raise exception 'only an Admin can resume campaigns';
  end if;
  update system_settings set campaigns_paused = false, paused_by = null, paused_at = null where id = 1;
  perform log_audit('resume_campaigns', 'system_settings', '1', null);
end $$;

-- ── Suppression helper ──────────────────────────────────────────────────────
-- One code path for suppressing a contact: inserts the permanent record,
-- flips the agent flags, cancels queued sends. Used by webhooks (STOP,
-- unsubscribe, complaint) and the admin add-only screen.
create or replace function suppress_contact(
  p_email text,
  p_phone text,
  p_agent_id uuid,
  p_type suppression_type,
  p_method text,
  p_source_message text default null,
  p_note text default null
) returns uuid
language plpgsql security definer set search_path = public as $$
declare
  v_id uuid;
begin
  insert into suppression_list (email, phone, agent_id, suppression_type, method, source_message, note, created_by)
  values (nullif(p_email, '')::citext, nullif(p_phone, ''), p_agent_id, p_type, p_method, p_source_message, p_note, auth.uid())
  returning id into v_id;

  if p_agent_id is not null then
    update agents set
      opted_out = true,
      opted_out_at = coalesce(opted_out_at, now()),
      outreach_paused = true,
      outreach_paused_reason = coalesce(outreach_paused_reason, 'suppressed: ' || p_type::text),
      response_status = 'opt_out'
    where id = p_agent_id;
    update email_queue set status = 'cancelled', last_error = 'contact suppressed'
    where agent_id = p_agent_id and status = 'queued';
  end if;

  perform log_audit('suppression_add', 'suppression_list', v_id::text,
    jsonb_build_object('type', p_type, 'method', p_method));
  return v_id;
end $$;

-- ── Rate limiting (public endpoints, Part 7) ────────────────────────────────
create or replace function check_rate_limit(p_bucket text, p_max int, p_window_seconds int)
returns boolean
language plpgsql security definer set search_path = public as $$
declare
  v_window timestamptz := to_timestamp(floor(extract(epoch from now()) / p_window_seconds) * p_window_seconds);
  v_hits int;
begin
  insert into rate_limits (bucket, window_start, hits)
  values (p_bucket, v_window, 1)
  on conflict (bucket, window_start) do update set hits = rate_limits.hits + 1
  returning hits into v_hits;
  delete from rate_limits where window_start < now() - interval '1 day';
  return v_hits <= p_max;
end $$;

-- ── Deduplication (Part 2) ──────────────────────────────────────────────────
create or replace function find_agent_duplicates(
  p_email text, p_phone text, p_first text, p_last text, p_brokerage text, p_license text
) returns table (agent_id uuid, match_reason text, similarity real)
language sql stable security definer set search_path = public as $$
  select a.id, 'exact email match', 1.0::real
  from agents a
  where a.deleted_at is null and p_email is not null and p_email <> ''
    and lower(a.business_email::text) = lower(p_email)
  union all
  select a.id, 'normalized phone match', 1.0::real
  from agents a
  where a.deleted_at is null and norm_phone(p_phone) is not null
    and a.phone_normalized = norm_phone(p_phone)
  union all
  select a.id, 'license number match', 1.0::real
  from agents a
  where a.deleted_at is null and p_license is not null and btrim(p_license) <> ''
    and lower(coalesce(a.license_number, '')) = lower(btrim(p_license))
  union all
  select a.id, 'fuzzy name + brokerage match',
    similarity(a.first_name || ' ' || a.last_name || ' ' || a.brokerage,
               coalesce(p_first,'') || ' ' || coalesce(p_last,'') || ' ' || coalesce(p_brokerage,''))
  from agents a
  where a.deleted_at is null
    and similarity(a.first_name || ' ' || a.last_name || ' ' || a.brokerage,
                   coalesce(p_first,'') || ' ' || coalesce(p_last,'') || ' ' || coalesce(p_brokerage,'')) > 0.55;
$$;

-- ── Priority scoring (Part 3) ───────────────────────────────────────────────
-- Legitimate business signals ONLY. Ordering influence only — never
-- compliance behavior.
create or replace function compute_priority(p_agent_id uuid)
returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare
  v_score int := 0;
  v_reasons jsonb := '[]'::jsonb;
  v_n int;
  v_settings system_settings%rowtype;
begin
  select * into v_settings from system_settings where id = 1;

  select count(*) into v_n from listings
  where agent_id = p_agent_id and status = 'active' and deleted_at is null;
  if v_n > 0 then
    v_score := v_score + least(v_n * 3, 12);
    v_reasons := v_reasons || jsonb_build_object('reason', v_n || ' active listing(s)', 'points', least(v_n * 3, 12));
  end if;

  select count(*) into v_n from listings
  where agent_id = p_agent_id and status = 'active' and deleted_at is null
    and county = any (v_settings.target_counties);
  if v_n > 0 then
    v_score := v_score + 5;
    v_reasons := v_reasons || jsonb_build_object('reason', 'listings in target counties', 'points', 5);
  end if;

  select count(*) into v_n from listings
  where agent_id = p_agent_id and status = 'active' and deleted_at is null
    and listing_date >= current_date - 14;
  if v_n > 0 then
    v_score := v_score + 4;
    v_reasons := v_reasons || jsonb_build_object('reason', 'newly listed property', 'points', 4);
  end if;

  select count(*) into v_n from listings
  where agent_id = p_agent_id and status in ('active', 'pending') and deleted_at is null
    and est_closing_date between current_date and current_date + 30;
  if v_n > 0 then
    v_score := v_score + 4;
    v_reasons := v_reasons || jsonb_build_object('reason', 'listing approaching estimated closing', 'points', 4);
  end if;

  if exists (
    select 1 from outreach_events
    where agent_id = p_agent_id and direction = 'inbound'
  ) then
    v_score := v_score + 8;
    v_reasons := v_reasons || jsonb_build_object('reason', 'prior response to our outreach', 'points', 8);
  end if;

  select count(*) into v_n from referrals where agent_id = p_agent_id and deleted_at is null;
  if v_n > 0 then
    v_score := v_score + least(10 + (v_n - 1) * 3, 19);
    v_reasons := v_reasons || jsonb_build_object('reason', v_n || ' prior referral(s) to our office', 'points', least(10 + (v_n - 1) * 3, 19));
  end if;

  if (select works_first_time_buyers from agents where id = p_agent_id) then
    v_score := v_score + 5;
    v_reasons := v_reasons || jsonb_build_object('reason', 'works with first-time buyers', 'points', 5);
  end if;

  select count(*) into v_n
  from listing_flags f join listings l on l.id = f.listing_id
  where l.agent_id = p_agent_id and l.deleted_at is null;
  if v_n > 0 then
    v_score := v_score + 6;
    v_reasons := v_reasons || jsonb_build_object('reason', 'sells properties with insurance complications', 'points', 6);
  end if;

  if (select requested_insurance_resource from agents where id = p_agent_id) then
    v_score := v_score + 10;
    v_reasons := v_reasons || jsonb_build_object('reason', 'explicitly requested an insurance resource', 'points', 10);
  end if;

  return jsonb_build_object('score', v_score, 'reasons', v_reasons);
end $$;

create or replace function refresh_priorities() returns int
language plpgsql security definer set search_path = public as $$
declare
  r record;
  v jsonb;
  n int := 0;
begin
  for r in select id from agents where deleted_at is null loop
    v := compute_priority(r.id);
    update agents set
      priority_score = (v ->> 'score')::int,
      priority_reasons = v -> 'reasons'
    where id = r.id;
    n := n + 1;
  end loop;
  return n;
end $$;

-- ── Follow-up scheduling (Part 4) ──────────────────────────────────────────
-- Marks contacts follow_up_due after the admin-configured business-day wait
-- with no response, and enqueues the single permitted follow-up. Processing
-- re-checks every rule at send time.
create or replace function mark_followups_due() returns int
language plpgsql security definer set search_path = public as $$
declare
  v_settings system_settings%rowtype;
  v_template templates%rowtype;
  r record;
  n int := 0;
begin
  select * into v_settings from system_settings where id = 1;
  select * into v_template from templates where kind = 'follow_up_email' and status = 'approved';
  if v_template.id is null then
    return 0;
  end if;

  for r in
    select a.id as agent_id, initial.occurred_at as initial_at
    from agents a
    join lateral (
      select occurred_at from outreach_events oe
      where oe.agent_id = a.id and oe.channel = 'email' and oe.direction = 'outbound'
        and oe.template_kind in ('initial_email', 'listing_email')
      order by occurred_at asc limit 1
    ) initial on true
    where a.deleted_at is null
      and a.stage = 'initial_email_sent'
      and not a.opted_out and not a.do_not_contact and not a.outreach_paused
      and add_business_days(initial.occurred_at::date, v_settings.follow_up_wait_business_days) <= current_date
      -- no inbound response since the initial email
      and not exists (
        select 1 from outreach_events oe
        where oe.agent_id = a.id and oe.direction = 'inbound' and oe.occurred_at >= initial.occurred_at
      )
      -- no follow-up already sent or queued
      and not exists (
        select 1 from outreach_events oe
        where oe.agent_id = a.id and oe.template_kind = 'follow_up_email' and oe.direction = 'outbound'
      )
      and not exists (
        select 1 from email_queue q
        where q.agent_id = a.id and q.kind = 'follow_up_email' and q.status in ('queued', 'processing')
      )
  loop
    update agents set stage = 'follow_up_due' where id = r.agent_id;
    insert into email_queue (agent_id, template_id, kind, scheduled_for)
    values (r.agent_id, v_template.id, 'follow_up_email', now());
    n := n + 1;
  end loop;
  return n;
end $$;

-- ── Operational notifications (Part 5) ─────────────────────────────────────
create or replace function generate_operational_notifications() returns int
language plpgsql security definer set search_path = public as $$
declare
  r record;
  n int := 0;
begin
  -- Closing within seven days
  for r in
    select rf.id, rf.assigned_producer, rf.client_name, rf.est_closing_date
    from referrals rf
    where rf.deleted_at is null and rf.assigned_producer is not null
      and rf.est_closing_date between current_date and current_date + 7
      and rf.quote_status not in ('closed_won', 'closed_lost', 'evidence_delivered')
      and not exists (
        select 1 from notifications nt
        where nt.referral_id = rf.id and nt.type = 'closing_soon'
          and nt.created_at::date = current_date
      )
  loop
    insert into notifications (user_id, type, title, body, referral_id)
    values (r.assigned_producer, 'closing_soon',
      'Closing within 7 days',
      'Referral for ' || r.client_name || ' has an estimated closing on ' || r.est_closing_date || '.',
      r.id);
    n := n + 1;
  end loop;

  -- Evidence of insurance needed
  for r in
    select rf.id, rf.assigned_producer, rf.client_name, rf.evidence_deadline
    from referrals rf
    where rf.deleted_at is null and rf.assigned_producer is not null
      and rf.evidence_deadline is not null
      and rf.evidence_delivered_at is null
      and rf.evidence_deadline <= current_date + 3
      and not exists (
        select 1 from notifications nt
        where nt.referral_id = rf.id and nt.type = 'evidence_needed'
          and nt.created_at::date = current_date
      )
  loop
    insert into notifications (user_id, type, title, body, referral_id)
    values (r.assigned_producer, 'evidence_needed',
      'Evidence of insurance needed',
      'Evidence of insurance for ' || r.client_name || ' is due ' || r.evidence_deadline || '.',
      r.id);
    n := n + 1;
  end loop;

  -- Agent follow-up due (manual follow_up_date on the contact)
  for r in
    select a.id, a.assigned_producer, a.first_name, a.last_name
    from agents a
    where a.deleted_at is null and a.assigned_producer is not null
      and a.follow_up_date is not null and a.follow_up_date <= current_date
      and not exists (
        select 1 from notifications nt
        where nt.agent_id = a.id and nt.type = 'agent_followup_due'
          and nt.created_at::date = current_date
      )
  loop
    insert into notifications (user_id, type, title, body, agent_id)
    values (r.assigned_producer, 'agent_followup_due',
      'Agent follow-up due',
      'Follow up with ' || r.first_name || ' ' || r.last_name || '.',
      r.id);
    n := n + 1;
  end loop;

  return n;
end $$;
