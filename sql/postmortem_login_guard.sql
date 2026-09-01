-- ═══════════════════════════════════════════════════════════════════════════
-- THE LOGIN GUARD HAS NEVER RUN
--
-- 20260722000000_login_attempt_guard.sql ends with:
--
--   revoke execute on function is_login_blocked(text, text)
--     from public, anon, authenticated;
--   revoke execute on function record_login_attempt(text, text, boolean)
--     from public, anon, authenticated;
--
-- ...and never grants EXECUTE to anybody. Revoking from PUBLIC removes the
-- default grant every role inherits, so the functions became callable by NO
-- role at all — including service_role, which is exactly what
-- /api/auth/attempt uses (createAdminClient).
--
-- Every call therefore failed with "permission denied for function", the
-- route's catch turned that into a degraded 200, and sign-in carried on. The
-- fail-open behaviour is deliberate and correct — an auth-telemetry outage must
-- never lock the agency out of its own CRM — but it meant the failure was
-- invisible except in server logs. Seen in the local dev log as:
--   [auth-guard] attempt tracking failed: Error: permission denied for
--   function is_login_blocked
--
-- TWO ENVIRONMENTS, TWO CAUSES, SAME DEAD FEATURE. The hosted project already
-- shows service_role on both functions: it was provisioned under an older
-- Supabase image that grants each API role explicitly, so revoking from PUBLIC
-- did not touch it. Local relies on the PUBLIC grant, so the revoke killed it.
-- This is the same environment drift that made table privileges diverge (see
-- 20260730120000_explicit_table_grants.sql) — the lesson holds: never leave an
-- authorization surface to an implicit default.
--
-- Production is nonetheless ALSO dead, for a different reason:
-- auth_attempts has zero rows there because SUPABASE_SERVICE_ROLE_KEY is not
-- set in Vercel, so createAdminClient() throws before it can call anything.
-- This migration fixes the database half in both environments; production
-- additionally needs that key set.
--
-- The fix is one grant, to one role: the ONLY caller. Deliberately NOT granted
-- to anon or authenticated — a browser that could call is_login_blocked could
-- probe whether an address is currently locked out, and one that could call
-- record_login_attempt could forge or flood attempt history.
-- ═══════════════════════════════════════════════════════════════════════════

grant execute on function is_login_blocked(text, text) to service_role;
grant execute on function record_login_attempt(text, text, boolean) to service_role;

-- Re-assert the negative side so this stays true if the functions are replaced.
revoke execute on function is_login_blocked(text, text) from public, anon, authenticated;
revoke execute on function record_login_attempt(text, text, boolean) from public, anon, authenticated;
