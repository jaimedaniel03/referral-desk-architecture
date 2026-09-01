  it('blocks a suppressed address (suppression list is consulted via RPC)', async () => {
    const result = await checkEmailSendable(db({ suppressed: true }), agent(), 'initial_email');
    expect(result.allowed).toBe(false);
    expect(result.reasons.join(' ')).toMatch(/suppression list/i);
  });
});

describe('checkEmailSendable — sequence cap (one initial + at most one follow-up)', () => {
  it('blocks a second initial once one initial exists', async () => {
    const database = db({ priorEvents: [{ template_kind: 'initial_email' }] });
    const result = await checkEmailSendable(database, agent(), 'initial_email');
    expect(result.allowed).toBe(false);
    expect(result.reasons.join(' ')).toMatch(/already sent once/i);
  });

  it('a listing email counts as the initial touch too', async () => {
    const database = db({ priorEvents: [{ template_kind: 'listing_email' }] });
    const result = await checkEmailSendable(database, agent(), 'initial_email');
    expect(result.allowed).toBe(false);
    expect(result.reasons.join(' ')).toMatch(/already sent once/i);
  });

  it('allows the single follow-up after the initial', async () => {
    const database = db({ priorEvents: [{ template_kind: 'initial_email' }] });
    const result = await checkEmailSendable(
      database,
      agent({ stage: 'initial_email_sent' }),
      'follow_up_email',
    );
    expect(result.reasons).toEqual([]);
    expect(result.allowed).toBe(true);
  });

  it('blocks a follow-up that would lead the sequence (no initial on record)', async () => {
    const result = await checkEmailSendable(
      db(),
      agent({ stage: 'initial_email_sent' }),
      'follow_up_email',
    );
    expect(result.allowed).toBe(false);
    expect(result.reasons.join(' ')).toMatch(/no initial email/i);
  });

  it('blocks a second follow-up permanently', async () => {
    const database = db({
      priorEvents: [{ template_kind: 'initial_email' }, { template_kind: 'follow_up_email' }],
    });
    const result = await checkEmailSendable(
      database,
      agent({ stage: 'initial_email_sent' }),
      'follow_up_email',
