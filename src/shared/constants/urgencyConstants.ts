import { Urgency } from '@/shared/types';

/**
 * How an urgency reads to a user: High / Medium / Low.
 *
 * The stored codes are still `hot`/`warm`/`cold` — they are a Postgres enum on
 * prospects, notes, cl_leads and cl_paid_referrals, so the wire values are not
 * ours to rename without a migration across all four. But "Hot / Warm / Cold" is
 * LEAD-TEMPERATURE vocabulary: it describes how likely a lead is to convert, not
 * how soon someone must act. Reading it as urgency, a user has to translate
 * "Cold" into "low priority" every time, and the two scales genuinely disagree —
 * a lukewarm inquiry with a discharge tomorrow is high urgency and a warm lead.
 *
 * So the codes stay and the LABEL is the urgency scale. Every screen renders
 * through this map (chips, pills, form options, filters), which is what keeps
 * the two from drifting apart.
 */
export const URGENCY_LABELS: Record<Urgency, string> = {
  [Urgency.Hot]: 'High',
  [Urgency.Warm]: 'Medium',
  [Urgency.Cold]: 'Low',
};

/**
 * Colour only — the SHAPE comes from <Pill tone="none">, so an urgency chip is
 * the same object as a status badge sitting beside it. The two used to be drawn
 * with their own geometry at each call site (`px-2.5 py-0.5 text-[10px]` on the
 * activity feed against `px-2 py-0.5 text-[9px]` on a pipeline card), which is
 * why the same urgency badge was a different size on every screen.
 *
 * `border` is included here rather than left to the caller so the tone is
 * self-contained: these are outlined tints, unlike the pastel-filled status
 * pills, and the outline is part of what makes them a different KIND of badge.
 */
export const URGENCY_TONE: Record<Urgency, string> = {
  [Urgency.Hot]: 'border border-destructive/30 bg-destructive/10 text-destructive',
  [Urgency.Warm]: 'border border-warning/30 bg-warning/10 text-warning',
  [Urgency.Cold]: 'border border-azure/30 bg-azure/10 text-azure',
};
