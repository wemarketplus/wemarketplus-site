import { Urgency } from '@/shared/types';

export const URGENCY_LABELS: Record<Urgency, string> = {
  [Urgency.Hot]: 'Hot',
  [Urgency.Warm]: 'Warm',
  [Urgency.Cold]: 'Cold',
};

/**
 * Colour only — the SHAPE comes from <Pill tone="none">, so an urgency chip is
 * the same object as a status badge sitting beside it. The two used to be drawn
 * with their own geometry at each call site (`px-2.5 py-0.5 text-[10px]` on the
 * activity feed against `px-2 py-0.5 text-[9px]` on a pipeline card), which is
 * why the same Hot/Warm/Cold badge was a different size on every screen.
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
