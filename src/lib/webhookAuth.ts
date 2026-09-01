// (production file imports "server-only"; removed here so the suite runs standalone)
import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Constant-time secret verification for webhooks and cron endpoints.
 *
 * Secrets must be compared without leaking their length or content through
 * timing. We SHA-256 both sides to fixed-length digests (so length never
 * differs) and compare those with crypto.timingSafeEqual. Never use === / !==
 * on a secret, and never accept a secret from a query string (it lands in
 * access logs, Referer headers, and browser history) — require a header.
 */

/** Length- and timing-safe string equality. */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const ha = createHash('sha256').update(a).digest();
  const hb = createHash('sha256').update(b).digest();
  return timingSafeEqual(ha, hb);
}

export interface AuthResult {
  ok: boolean;
  status: number;
  error?: string;
}

/**
 * Verify `Authorization: Bearer <secret>`. This is exactly what Vercel Cron
 * sends when CRON_SECRET is configured. Fails closed (503) when the expected
 * secret is not configured.
 */
export function verifyBearerSecret(req: Request, secret: string | undefined): AuthResult {
  if (!secret) return { ok: false, status: 503, error: 'secret not configured' };
  const header = req.headers.get('authorization') ?? '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  const provided = match?.[1]?.trim() ?? '';
  if (provided && timingSafeEqualStr(provided, secret)) return { ok: true, status: 200 };
  return { ok: false, status: 401, error: 'unauthorized' };
}

/**
 * Verify a shared secret carried in a request header (constant-time).
 * Returns false when the secret is unconfigured or the header is missing.
 */
export function verifyHeaderSecret(req: Request, headerName: string, secret: string | undefined): boolean {
  if (!secret) return false;
  const provided = req.headers.get(headerName)?.trim() ?? '';
  return provided.length > 0 && timingSafeEqualStr(provided, secret);
}
