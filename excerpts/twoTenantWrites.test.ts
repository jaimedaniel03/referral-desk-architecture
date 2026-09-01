import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { randomUUID } from 'node:crypto';

/**
 * WHAT BREAKS THE DAY A SECOND AGENCY GOES LIVE.
 *
 * Every write below happens with NO user session — cron jobs, provider
 * webhooks, the credit ledger, the public signup form. While one organization
 * was active the database could infer the tenant unambiguously, so none of this
 * was exercised. A second organization removes that inference, and anything
 * that never learned to state its tenant stops working.
 *
 * These ran red before the fix:
 *   credit ledger        → organization_id is required on credit_transactions
 *   inbound webhook      → organization_id is required on AUDIT_LOG
 *   unsubscribe / STOP   → organization_id is required on suppression_list
 *
 * The audit_log one was the widest: almost every write in this system fires an
 * audit trigger, so a single missing check would have made the second agency's
 * launch a near-total write outage, reported with an error naming a table
 * nowhere near the cause.
 */

const admin: SupabaseClient = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
  { auth: { autoRefreshToken: false, persistSession: false } },
);

const FIRST_ORG = '00000000-0000-0000-0000-00000000ffff';
const stamp = randomUUID().slice(0, 8);
let secondOrg: string;
let agentId: string;

beforeAll(async () => {
  const { data, error } = await admin
    .from('organizations')
    .insert({ name: `Second Agency ${stamp}`, slug: `second-${stamp}` })
    .select('id')
    .single();
  if (error) throw new Error(`second org: ${error.message}`);
  secondOrg = data.id;

  const { data: a } = await admin.from('agents').select('id').limit(1).single();
  agentId = a!.id;
}, 60_000);

afterAll(async () => {
  // Organizations are terminated, never deleted — audit rows reference them.
  if (secondOrg) await admin.from('organizations').update({ status: 'terminated' }).eq('id', secondOrg);
});

describe('privileged, session-less writes survive a second tenant', () => {
  it('two organizations really are active during this test', async () => {
    const { count } = await admin
      .from('organizations')
      .select('id', { count: 'exact', head: true })
      .eq('status', 'active');
    expect(count, 'the test is meaningless with one org').toBeGreaterThanOrEqual(2);
  });

  it('the credit ledger charges the organization it was told about', async () => {
    const { data, error } = await admin.rpc('debit_credits', {
      p_action: 'territory_scan_zip',
      p_quantity: 1,
      p_entity_type: 'scan_runs',
      p_entity_id: randomUUID(),
      p_idempotency_key: `test-${randomUUID()}`,
      p_note: 'two-tenant probe',
      p_organization_id: FIRST_ORG,
    });
    expect(error, error?.message).toBeNull();
    expect((data as { ok: boolean }).ok).toBe(true);
  });

  it('an inbound webhook can still record what a professional sent us', async () => {
    // Derives its tenant from the agent; the audit trigger it fires must not veto it.
    const { error } = await admin.from('outreach_events').insert({
      agent_id: agentId,
      channel: 'email',
      direction: 'inbound',
      body: 'probe',
      from_identity: 'them@example.test',
      to_identity: 'office@example.test',
    });
    expect(error, error?.message).toBeNull();
  });

  it('an unsubscribe from someone we cannot identify still records AND blocks sending', async () => {
    // The common case: a one-click link works for a person the system cannot
    // otherwise match, so there is no agent to derive a tenant from.
    const email = `stop-${randomUUID()}@example.test`;
    const { error } = await admin.rpc('suppress_contact', {
      p_email: email,
      p_phone: null,
      p_agent_id: null,
      p_type: 'email_unsubscribe',
      p_method: 'one-click unsubscribe link',
      p_source_message: null,
      p_note: null,
    });
    expect(error, error?.message).toBeNull();

    const { data: blocked } = await admin.rpc('is_email_suppressed', { p_email: email });
    expect(blocked, 'recorded but the send path cannot see it').toBe(true);
  });

  it('an SMS STOP still records', async () => {
    const { error } = await admin.rpc('suppress_contact', {
      p_email: null,
      p_phone: `+1555555${Math.floor(1000 + Math.random() * 8999)}`,
      p_agent_id: null,
      p_type: 'sms_stop',
      p_method: 'STOP keyword',
      p_source_message: 'STOP',
      p_note: null,
    });
    expect(error, error?.message).toBeNull();
  });

  it('a genuinely ambiguous write still refuses, loudly and by name', async () => {
    // A public signup has no session and no parent, and which agency owns it is
    // a territory question this product has not answered yet. Refusing with a
    // clear message beats guessing an agency or vanishing silently.
    const { error } = await admin.from('dedup_queue').insert({
      candidate: { first_name: 'Public', last_name: 'Signup' },
      matched_agent_id: null,
      match_reasons: [],
      source: 'agent_self_submission',
      status: 'pending',
    });
    expect(error).not.toBeNull();
    expect(error!.message).toMatch(/organization_id is required on dedup_queue/);
  });
});
