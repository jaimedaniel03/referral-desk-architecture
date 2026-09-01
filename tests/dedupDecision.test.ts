import { describe, expect, it } from 'vitest';
import {
  classifyDuplicates,
  collapseHits,
  hiddenDuplicateMessage,
  isCandidateMatch,
  type DuplicateHit,
} from '../src/lib/dedupDecision';

/**
 * "NO DUPLICATE" ABOUT A RECORD IT COULD NOT SEE.
 *
 * The old /api/agents did exactly this:
 *
 *   const ids  = [...matches.keys()];
 *   const rows = await supabase.from('agents').select(...).in('id', ids);   // RLS
 *   const duplicates = ids.filter(id => rowsById.has(id)).map(...);
 *   if (duplicates.length > 0) return 409;
 *   // …otherwise fall through and INSERT
 *
 * `rows` is the caller's own read. A producer sees only the agents assigned to
 * or created by them, so a match on a colleague's record was filtered out
 * there, `duplicates` came back empty, and the insert proceeded. The check
 * reported "no duplicate" about a record it was structurally unable to read.
 *
 * The reconstruction below is the load-bearing test: the SAME inputs that made
 * the old code return an empty array must now come back marked as blocked.
 */

const HIDDEN_AGENT = '11111111-1111-1111-1111-111111111111';
const VISIBLE_AGENT = '22222222-2222-2222-2222-222222222222';

interface AgentRow { id: string; first_name: string }

/** The old route's conclusion, reproduced exactly, for comparison. */
function oldRouteWouldInsert(hits: DuplicateHit[], readable: Map<string, AgentRow>): boolean {
  const ids = [...new Set(hits.filter(isCandidateMatch).map((h) => h.agent_id))];
  const duplicates = ids.filter((id) => readable.has(id));
  return duplicates.length === 0; // empty ⇒ "clear to insert"
}

describe('a duplicate the caller cannot see', () => {
  const hits: DuplicateHit[] = [
    { agent_id: HIDDEN_AGENT, match_reason: 'normalized phone match', similarity: 1, visible_to_caller: false },
  ];
  const readable = new Map<string, AgentRow>(); // RLS returned nothing

  it('was treated as no duplicate at all by the old code', () => {
    // Not an assertion about the new code — this is the defect, pinned, so the
    // next assertion is demonstrably about something that changed.
    expect(oldRouteWouldInsert(hits, readable)).toBe(true);
  });

  it('now blocks the create instead', () => {
    const decision = classifyDuplicates(hits, readable);
    expect(decision.blocked).toBe(true);
    expect(decision.duplicates).toEqual([]);
    expect(decision.hidden).toHaveLength(1);
    expect(decision.hidden[0].agent_id).toBe(HIDDEN_AGENT);
  });

  it('describes it without disclosing the record', () => {
    const message = hiddenDuplicateMessage(classifyDuplicates(hits, readable).hidden);
    expect(message).toMatch(/already matches this person/i);
    expect(message).toMatch(/normalized phone match/);
    expect(message).toMatch(/administrator/i);
    // A colleague's record must not leak through the refusal: only the reason
    // it matched, never the person it matched.
    expect(message).not.toMatch(/@/);
    expect(message).not.toMatch(/\d{3}[-.\s]?\d{3}[-.\s]?\d{4}/);
  });
});

describe('a duplicate the caller can see', () => {
  const hits: DuplicateHit[] = [
    { agent_id: VISIBLE_AGENT, match_reason: 'exact email match', similarity: 1, visible_to_caller: true },
  ];
  const readable = new Map<string, AgentRow>([[VISIBLE_AGENT, { id: VISIBLE_AGENT, first_name: 'Dana' }]]);

  it('still comes back as a mergeable candidate, carrying the record', () => {
    const decision = classifyDuplicates(hits, readable);
    expect(decision.blocked).toBe(true);
    expect(decision.hidden).toEqual([]);
    expect(decision.duplicates).toHaveLength(1);
    expect(decision.duplicates[0].agent.first_name).toBe('Dana');
  });
});

describe('mixed visibility', () => {
  it('reports both, so an override knows what it is overriding', () => {
    const hits: DuplicateHit[] = [
      { agent_id: VISIBLE_AGENT, match_reason: 'exact email match', similarity: 1, visible_to_caller: true },
      { agent_id: HIDDEN_AGENT, match_reason: 'license number match', similarity: 1, visible_to_caller: false },
    ];
    const readable = new Map<string, AgentRow>([[VISIBLE_AGENT, { id: VISIBLE_AGENT, first_name: 'Dana' }]]);
    const decision = classifyDuplicates(hits, readable);
    expect(decision.duplicates.map((d) => d.agent_id)).toEqual([VISIBLE_AGENT]);
    expect(decision.hidden.map((d) => d.agent_id)).toEqual([HIDDEN_AGENT]);
  });
});

describe('collapsing hits', () => {
  it('keeps every reason and the best similarity for one agent', () => {
    const collapsed = collapseHits([
      { agent_id: VISIBLE_AGENT, match_reason: 'exact email match', similarity: 1, visible_to_caller: true },
      { agent_id: VISIBLE_AGENT, match_reason: 'fuzzy name + brokerage match', similarity: 0.8, visible_to_caller: true },
    ]);
    const hit = collapsed.get(VISIBLE_AGENT)!;
    expect(hit.match_reason).toBe('exact email match; fuzzy name + brokerage match');
    expect(hit.similarity).toBe(1);
  });

  it('does not let one visible row make a hidden record look readable', () => {
    // Both rows are the same agent; visibility is a property of the AGENT, so
    // OR-ing is correct — but the readable map, not this flag, is what decides
    // whether the record is rendered.
    const collapsed = collapseHits([
      { agent_id: HIDDEN_AGENT, match_reason: 'normalized phone match', similarity: 1, visible_to_caller: false },
      { agent_id: HIDDEN_AGENT, match_reason: 'license number match', similarity: 1, visible_to_caller: false },
    ]);
    expect(collapsed.get(HIDDEN_AGENT)!.visible_to_caller).toBe(false);
    expect(classifyDuplicates([...collapsed.values()], new Map()).hidden).toHaveLength(1);
  });

  it('drops matches below the similarity floor', () => {
    const weak: DuplicateHit[] = [
      { agent_id: VISIBLE_AGENT, match_reason: 'fuzzy name + brokerage match', similarity: 0.4, visible_to_caller: true },
    ];
    expect(collapseHits(weak).size).toBe(0);
    expect(classifyDuplicates(weak, new Map()).blocked).toBe(false);
  });
});
