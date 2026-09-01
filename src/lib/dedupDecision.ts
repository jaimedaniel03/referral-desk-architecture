/**
 * What the duplicate check is allowed to conclude.
 *
 * THE DEFECT THIS FILE EXISTS FOR
 * ------------------------------
 * /api/agents asked the database for duplicate candidates, then re-read the
 * matched ids through the caller's own row-level security in order to render
 * them. Producer compartmentalization means a producer can only read the
 * agents assigned to or created by them, so a match on a colleague's record
 * came back from the matcher and disappeared on the re-read. The route then
 * looked at an empty array and concluded "no duplicate" — about a record it
 * was structurally incapable of seeing — and inserted a second record for a
 * person the agency already had.
 *
 * The rule, stated once, here: a match that cannot be shown is still a match.
 * Invisible is not absent. The two outcomes are separate on purpose, because
 * they need different words on screen: one can be merged into, the other can
 * only be escalated.
 */

export interface DuplicateHit {
  agent_id: string;
  match_reason: string;
  similarity: number;
  /** Whether the caller may READ the matched record (from can_access_agent). */
  visible_to_caller: boolean;
}

export interface VisibleDuplicate<TAgent> {
  agent_id: string;
  match_reason: string;
  similarity: number;
  agent: TAgent;
}

export interface HiddenDuplicate {
  agent_id: string;
  match_reason: string;
  similarity: number;
}

export interface DuplicateDecision<TAgent> {
  /** Matches the caller may see, and may therefore merge into. */
  duplicates: VisibleDuplicate<TAgent>[];
  /** Matches inside the same tenant that the caller may not read. */
  hidden: HiddenDuplicate[];
  /** True when a create must be refused unless explicitly forced. */
  blocked: boolean;
}

/**
 * The similarity floor the product has always used: an exact identifier match
 * scores 1.0, and a fuzzy name+brokerage match has to clear 0.55.
 */
export function isCandidateMatch(hit: { similarity: number }): boolean {
  return hit.similarity > 0.55 || hit.similarity >= 1;
}

/**
 * Collapse several match reasons for the same agent into one entry, keeping
 * the best similarity. Visibility is OR-ed: if any row for that agent says the
 * caller can read it, the caller can read it.
 */
export function collapseHits(hits: DuplicateHit[]): Map<string, DuplicateHit> {
  const byAgent = new Map<string, DuplicateHit>();
  for (const hit of hits) {
    if (!isCandidateMatch(hit)) continue;
    const existing = byAgent.get(hit.agent_id);
    if (!existing) {
      byAgent.set(hit.agent_id, { ...hit });
      continue;
    }
    if (!existing.match_reason.split('; ').includes(hit.match_reason)) {
      existing.match_reason = `${existing.match_reason}; ${hit.match_reason}`;
    }
    existing.similarity = Math.max(existing.similarity, hit.similarity);
    existing.visible_to_caller = existing.visible_to_caller || hit.visible_to_caller;
  }
  return byAgent;
}

/**
 * Split candidate matches into the ones the caller can be shown and the ones
 * that exist but cannot be. `readable` is what came back when the matched ids
 * were re-read through RLS — an id missing from it is hidden, NOT absent.
 */
export function classifyDuplicates<TAgent>(
  hits: DuplicateHit[],
  readable: Map<string, TAgent>,
): DuplicateDecision<TAgent> {
  const byAgent = collapseHits(hits);
  const duplicates: VisibleDuplicate<TAgent>[] = [];
  const hidden: HiddenDuplicate[] = [];

  for (const [agentId, hit] of byAgent) {
    const agent = readable.get(agentId);
    if (agent !== undefined) {
      duplicates.push({
        agent_id: agentId,
        match_reason: hit.match_reason,
        similarity: hit.similarity,
        agent,
      });
    } else {
      hidden.push({
        agent_id: agentId,
        match_reason: hit.match_reason,
        similarity: hit.similarity,
      });
    }
  }

  return { duplicates, hidden, blocked: duplicates.length > 0 || hidden.length > 0 };
}

/**
 * What to tell somebody about a match they are not allowed to see. It names
 * the reason it matched and nothing else — no name, no email, no phone. The
 * point is to stop the create and route the person to somebody who can resolve
 * it, not to leak a colleague's record through an error message.
 */
export function hiddenDuplicateMessage(hidden: HiddenDuplicate[]): string {
  const reasons = [...new Set(hidden.map((h) => h.match_reason))].join('; ');
  const many = hidden.length !== 1;
  return (
    `${many ? `${hidden.length} records` : 'A record'} in this agency already `
    + `${many ? 'match' : 'matches'} this person (${reasons}), but `
    + `${many ? 'they are' : 'it is'} assigned to another producer, so `
    + `${many ? 'they cannot' : 'it cannot'} be shown here and you cannot merge into `
    + `${many ? 'them' : 'it'}. Ask an administrator to reassign the record or perform the merge — `
    + 'creating a second one would split the relationship.'
  );
}
