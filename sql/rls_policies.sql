-- ═══════════════════════════════════════════════════════════════════════════
-- Referral Desk — Row Level Security and privilege revocation
-- Every table gets RLS. Role checks live in Postgres, never frontend-only.
-- ═══════════════════════════════════════════════════════════════════════════

alter table profiles         enable row level security;
alter table system_settings  enable row level security;
alter table agents           enable row level security;
alter table consent_records  enable row level security;
alter table listings         enable row level security;
alter table listing_flags    enable row level security;
alter table templates        enable row level security;
alter table campaigns        enable row level security;
alter table outreach_events  enable row level security;
alter table email_events     enable row level security;
alter table referrals        enable row level security;
alter table suppression_list enable row level security;
alter table email_queue      enable row level security;
alter table review_queue     enable row level security;
alter table tasks            enable row level security;
alter table notifications    enable row level security;
alter table audit_log        enable row level security;
alter table dedup_queue      enable row level security;
alter table rate_limits      enable row level security;

-- ── Privilege revocation (belt under the RLS suspenders) ────────────────────
-- The suppression list is permanent: nobody — not even the service role —
-- holds UPDATE/DELETE/TRUNCATE. Append-only tables lose UPDATE/DELETE too.
revoke update, delete, truncate on suppression_list from anon, authenticated, service_role;
revoke update, delete, truncate on audit_log        from anon, authenticated, service_role;
revoke update, delete           on consent_records  from anon, authenticated, service_role;
revoke update, delete           on email_events     from anon, authenticated, service_role;
revoke delete                   on outreach_events  from anon, authenticated, service_role;

-- Soft-delete pattern everywhere: hard DELETE is revoked from app roles.
revoke delete on agents, listings, listing_flags, referrals, tasks,
               templates, campaigns, email_queue, review_queue,
               notifications, dedup_queue, profiles, system_settings
  from anon, authenticated;

-- anon (public web) touches NOTHING directly; public endpoints go through
-- server routes using the service role after rate limiting + validation.
revoke all on all tables in schema public from anon;

-- ── profiles ────────────────────────────────────────────────────────────────
create policy profiles_select on profiles
  for select to authenticated using (true);  -- small team; names needed for assignment

create policy profiles_update_self on profiles
  for update to authenticated
  using (id = auth.uid() or is_admin())
  with check (
    -- only admins may change roles or active status
    is_admin() or (
      id = auth.uid()
      and role = (select p.role from profiles p where p.id = auth.uid())
      and is_active = (select p.is_active from profiles p where p.id = auth.uid())
    )
  );

-- ── system_settings ────────────────────────────────────────────────────────
create policy settings_select on system_settings
  for select to authenticated using (true);

create policy settings_update_admin on system_settings
  for update to authenticated
  using (is_admin()) with check (is_admin());
-- (kill-switch pause is exposed to every employee via the
--  pause_all_campaigns() SECURITY DEFINER function, not via table update)

-- ── agents ──────────────────────────────────────────────────────────────────
create policy agents_select on agents
  for select to authenticated using (true);

create policy agents_insert on agents
  for insert to authenticated with check (true);

create policy agents_update on agents
  for update to authenticated
  using (is_admin() or assigned_producer = auth.uid() or created_by = auth.uid())
  with check (is_admin() or assigned_producer = auth.uid() or created_by = auth.uid());

-- ── consent_records (append-only; inserts by any employee) ─────────────────
create policy consent_select on consent_records
  for select to authenticated using (true);
create policy consent_insert on consent_records
  for insert to authenticated with check (recorded_by = auth.uid());

-- ── listings & flags ────────────────────────────────────────────────────────
create policy listings_select on listings for select to authenticated using (true);
create policy listings_insert on listings for insert to authenticated with check (true);
create policy listings_update on listings
  for update to authenticated
  using (
    is_admin()
    or exists (select 1 from agents a where a.id = agent_id and (a.assigned_producer = auth.uid() or a.created_by = auth.uid()))
  );

create policy flags_select on listing_flags for select to authenticated using (true);
create policy flags_insert on listing_flags for insert to authenticated with check (created_by = auth.uid());

-- ── templates (read all; write admin — Producers cannot edit templates) ────
create policy templates_select on templates for select to authenticated using (true);
create policy templates_insert on templates for insert to authenticated with check (is_admin());
create policy templates_update on templates for update to authenticated using (is_admin()) with check (is_admin());

-- ── campaigns (create by anyone; approve admin-only, checked in trigger+API) ─
create policy campaigns_select on campaigns for select to authenticated using (true);
create policy campaigns_insert on campaigns for insert to authenticated with check (created_by = auth.uid());
create policy campaigns_update on campaigns
  for update to authenticated
  using (is_admin() or created_by = auth.uid())
  with check (
    -- only an Admin can mark a campaign approved
    is_admin() or status not in ('approved')
  );

-- ── outreach_events ─────────────────────────────────────────────────────────
create policy outreach_select on outreach_events for select to authenticated using (true);
create policy outreach_insert on outreach_events
  for insert to authenticated
  with check (
    -- producers log sends/calls for their own assigned agents; admin anywhere
    is_admin()
    or agent_id is null
    or exists (
      select 1 from agents a
      where a.id = agent_id and (a.assigned_producer = auth.uid() or a.created_by = auth.uid())
    )
  );
-- status updates (delivery webhooks) arrive via service role only:
create policy outreach_update_service on outreach_events
  for update to authenticated using (false);

-- ── email_events (service-role writes via webhooks; team reads) ────────────
create policy email_events_select on email_events for select to authenticated using (true);

-- ── referrals (client PII: admin or assigned producer or creator only) ─────
create policy referrals_select on referrals
  for select to authenticated
  using (is_admin() or assigned_producer = auth.uid() or created_by = auth.uid());

create policy referrals_insert on referrals
  for insert to authenticated with check (created_by = auth.uid());

create policy referrals_update on referrals
  for update to authenticated
  using (is_admin() or assigned_producer = auth.uid() or created_by = auth.uid())
  with check (is_admin() or assigned_producer = auth.uid() or created_by = auth.uid());

-- ── suppression_list ────────────────────────────────────────────────────────
-- Everyone can READ (send paths + UI badges); only Admin can INSERT from the
-- app (webhook/system adds arrive via service role). Nobody can change rows.
create policy suppression_select on suppression_list
  for select to authenticated using (true);
create policy suppression_insert_admin on suppression_list
  for insert to authenticated with check (is_admin());

-- ── email_queue ─────────────────────────────────────────────────────────────
create policy queue_select on email_queue for select to authenticated using (true);
create policy queue_insert on email_queue
  for insert to authenticated
  with check (
    is_admin() or exists (
      select 1 from agents a
      where a.id = agent_id and (a.assigned_producer = auth.uid() or a.created_by = auth.uid())
    )
  );
create policy queue_update on email_queue
  for update to authenticated
  using (is_admin() or created_by = auth.uid())
  with check (
    -- employees may only cancel; processing status changes come from service role
    status in ('cancelled', 'queued')
  );

-- ── review_queue ────────────────────────────────────────────────────────────
create policy review_select on review_queue for select to authenticated using (true);
create policy review_update on review_queue
  for update to authenticated using (true)
  with check (reviewed_by = auth.uid() or reviewed_by is null);

-- ── tasks ───────────────────────────────────────────────────────────────────
create policy tasks_select on tasks for select to authenticated using (true);
create policy tasks_insert on tasks for insert to authenticated with check (created_by = auth.uid());
create policy tasks_update on tasks
  for update to authenticated
  using (is_admin() or assigned_to = auth.uid() or created_by = auth.uid());

-- ── notifications (own feed; admins see all) ───────────────────────────────
create policy notifications_select on notifications
  for select to authenticated using (user_id = auth.uid() or is_admin());
create policy notifications_update on notifications
  for update to authenticated using (user_id = auth.uid());
create policy notifications_insert on notifications
  for insert to authenticated with check (true);

-- ── audit_log (admin read; writes only via log_audit security definer) ─────
create policy audit_select_admin on audit_log
  for select to authenticated using (is_admin());

-- ── dedup_queue ─────────────────────────────────────────────────────────────
create policy dedup_select on dedup_queue for select to authenticated using (true);
create policy dedup_insert on dedup_queue for insert to authenticated with check (true);
create policy dedup_update on dedup_queue for update to authenticated using (true);

-- rate_limits: no app-role access at all (security definer function only).
revoke all on rate_limits from anon, authenticated;

-- ── Function execution grants ───────────────────────────────────────────────
grant execute on function pause_all_campaigns() to authenticated;
grant execute on function resume_campaigns() to authenticated;
grant execute on function is_admin() to authenticated;
grant execute on function log_audit(text, text, text, jsonb) to authenticated;
grant execute on function find_agent_duplicates(text, text, text, text, text, text) to authenticated;
grant execute on function compute_priority(uuid) to authenticated;
revoke execute on function suppress_contact(text, text, uuid, suppression_type, text, text, text) from anon, authenticated;
revoke execute on function check_rate_limit(text, int, int) from anon, authenticated;
