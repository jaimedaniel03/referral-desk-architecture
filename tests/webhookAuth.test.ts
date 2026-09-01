import { describe, it, expect } from 'vitest';
import { timingSafeEqualStr, verifyBearerSecret, verifyHeaderSecret } from '../src/lib/webhookAuth';

const SECRET = 'super-secret-cron-token-123';

function req(headers: Record<string, string>): Request {
  return new Request('https://example.test/api/cron/tick', { headers });
}

describe('timingSafeEqualStr', () => {
  it('true for equal strings, false otherwise (incl. different lengths)', () => {
    expect(timingSafeEqualStr(SECRET, SECRET)).toBe(true);
    expect(timingSafeEqualStr(SECRET, SECRET + 'x')).toBe(false);
    expect(timingSafeEqualStr(SECRET, 'short')).toBe(false);
    expect(timingSafeEqualStr('', '')).toBe(true);
  });
});

describe('verifyBearerSecret (cron)', () => {
  it('accepts a correct Bearer header', () => {
    expect(verifyBearerSecret(req({ authorization: `Bearer ${SECRET}` }), SECRET)).toEqual({ ok: true, status: 200 });
  });
  it('rejects a wrong secret / missing header / wrong scheme', () => {
    expect(verifyBearerSecret(req({ authorization: 'Bearer nope' }), SECRET).ok).toBe(false);
    expect(verifyBearerSecret(req({}), SECRET).ok).toBe(false);
    expect(verifyBearerSecret(req({ authorization: SECRET }), SECRET).ok).toBe(false); // no "Bearer "
  });
  it('does NOT accept a query-string secret (header-only)', () => {
    const r = new Request(`https://example.test/api/cron/tick?secret=${SECRET}`, {});
    expect(verifyBearerSecret(r, SECRET).ok).toBe(false);
  });
  it('fails closed (503) when the secret is unconfigured', () => {
    expect(verifyBearerSecret(req({ authorization: `Bearer ${SECRET}` }), undefined)).toEqual({
      ok: false,
      status: 503,
      error: 'secret not configured',
    });
  });
});

describe('verifyHeaderSecret (sms webhook)', () => {
  it('accepts the correct header value, rejects wrong/missing/unconfigured', () => {
    expect(verifyHeaderSecret(req({ 'x-webhook-auth': SECRET }), 'x-webhook-auth', SECRET)).toBe(true);
    expect(verifyHeaderSecret(req({ 'x-webhook-auth': 'wrong' }), 'x-webhook-auth', SECRET)).toBe(false);
    expect(verifyHeaderSecret(req({}), 'x-webhook-auth', SECRET)).toBe(false);
    expect(verifyHeaderSecret(req({ 'x-webhook-auth': SECRET }), 'x-webhook-auth', undefined)).toBe(false);
  });
});
