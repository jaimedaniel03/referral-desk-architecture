import { NextResponse } from 'next/server';
import { createAnonClient } from '@/lib/supabase/anon';
import { verifyResendWebhook } from '@/lib/email/resend';
import { normalizeInboundEmail, processInboundEmail } from '../inbound/handler';

export const dynamic = 'force-dynamic';

/**
 * Resend delivery webhook (svix-signed). Raw body is read FIRST — signature
 * verification happens over the exact bytes received.
 *
 * Bounces and complaints trigger permanent suppression via the service-role
 * suppress_contact RPC; delivery statuses only ever move forward (sent/opened
 * never downgrade a delivered/bounced/complained status).
 */

const DELIVERY_TYPES = [
  'email.sent',
  'email.delivered',
  'email.delivery_delayed',
  'email.bounced',
  'email.complained',
  'email.opened',
];

/** delivered/bounced/complained update the outreach event; the rest only log. */
const STATUS_MAP: Record<string, string> = {
  delivered: 'delivered',
  bounced: 'bounced',
  complained: 'complained',
};

function recipientFromPayload(data: Record<string, unknown>): string | null {
  const to = data.to;
  if (typeof to === 'string' && to.includes('@')) return to;
  if (Array.isArray(to) && typeof to[0] === 'string' && to[0].includes('@')) return to[0];
  return null;
}

export async function POST(req: Request) {
  const rawBody = await req.text();

  const secret = process.env.RESEND_WEBHOOK_SECRET;
  if (!secret) {
    return NextResponse.json({ error: 'webhook not configured' }, { status: 503 });
  }
  const valid = verifyResendWebhook({
    secret,
    svixId: req.headers.get('svix-id'),
    svixTimestamp: req.headers.get('svix-timestamp'),
    svixSignature: req.headers.get('svix-signature'),
    rawBody,
  });
  if (!valid) {
    return NextResponse.json({ error: 'invalid signature' }, { status: 401 });
  }

  let payload: { type?: string; data?: Record<string, unknown> };
  try {
    payload = JSON.parse(rawBody) as { type?: string; data?: Record<string, unknown> };
  } catch {
    return NextResponse.json({ error: 'invalid payload' }, { status: 400 });
  }
  const type = payload.type ?? '';
  const data = payload.data ?? {};

  // No privileged client. The provider SIGNATURE, verified above, is the gate;
  // the writes go through SECURITY DEFINER functions that can each express one
  // fact and nothing else. This route used to throw here in production, where
  // the service-role key is unset — so a hard bounce silently suppressed
  // nobody and a spam complaint was never recorded.
  const db = createAnonClient();

  try {
    if (type === 'email.received') {
      // Inbound reply arriving on the shared webhook — same pipeline as
      // /api/webhooks/inbound.
      const msg = normalizeInboundEmail(data);
      if (msg.from) await processInboundEmail(db, msg);
      return NextResponse.json({ received: true });
    }

    if (!DELIVERY_TYPES.includes(type)) {
      return NextResponse.json({ received: true });
    }

    const providerId =
      typeof data.email_id === 'string' ? data.email_id : typeof data.id === 'string' ? data.id : null;
    const suffix = type.replace(/^email\./, '');

    if (!providerId) {
      console.error('[webhooks/resend] event without provider message id:', type);
      return NextResponse.json({ received: true });
    }

    // One call records the callback and tells us who it was about, so the
    // route no longer needs to read outreach_events itself.
    const { data: outcome, error: outcomeError } = await db.rpc('record_delivery_outcome', {
      p_provider_message_id: providerId,
      p_status: STATUS_MAP[suffix] ?? null,
      p_event_type: suffix,
      p_payload: data,
    });
    if (outcomeError) {
      console.error('[webhooks/resend] delivery outcome not recorded:', providerId, outcomeError.message);
    }
    const event = (outcome ?? null) as
      { status?: string; agent_id?: string | null; to_identity?: string | null } | null;
    if (event?.status === 'no_matching_event') {
      console.error('[webhooks/resend] no outreach event for provider id', providerId, type);
    }

    const email = event?.to_identity ?? recipientFromPayload(data);
    const agentId = event?.agent_id ?? null;

    if (suffix === 'bounced') {
      // Suppression and the stage change happen together, in one function, so
      // a bounce cannot half-apply.
      const { error } = await db.rpc('record_undeliverable', {
        p_email: email,
        p_agent_id: agentId,
        p_reason: 'bounce',
        p_note: type,
      });
      if (error) console.error('[webhooks/resend] bounce not recorded:', error.message);
    }

    if (suffix === 'complained' && email) {
      const { error } = await db.rpc('record_undeliverable', {
        p_email: email,
        p_agent_id: agentId,
        p_reason: 'complaint',
        p_note: type,
      });
      if (error) console.error('[webhooks/resend] complaint not recorded:', error.message);
    }
  } catch (err) {
    // Verified event, processing hiccup — log loudly but return 200 so the
    // provider does not endlessly retry into the append-only event log.
    console.error('[webhooks/resend] processing error:', err);
  }

  return NextResponse.json({ received: true });
}
