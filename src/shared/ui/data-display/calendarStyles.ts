/**
 * The one selected-day treatment for a month grid.
 *
 * Both month views — Appointments (HospiceLink) and the CommunityLink calendar —
 * carried their own copy of `bg-primary/[0.06] ring-1 ring-inset ring-primary/40`,
 * and QA reported the same thing on both: after clicking a day you cannot tell
 * which one you picked. Three separate causes, all of which this fixes:
 *
 *   1. A 6% primary tint over white is #f4f7f6 — under a 1.03:1 difference from
 *      the neighbouring cells, so the fill was not perceptible at all.
 *   2. The ring was 1px at 40% alpha (~1.3:1 against white), well under the 3:1
 *      WCAG 1.4.11 floor for a UI component boundary.
 *   3. Worse, `hover:bg-foreground/[0.035]` sat in the SAME class list. Tailwind
 *      emits variant utilities after plain ones, so the hover fill won on source
 *      order and repainted the selected cell grey for exactly as long as the
 *      pointer was on it — i.e. during the moment the user looks to confirm what
 *      they just clicked. `SELECTED_DAY_CELL` therefore restates `hover:` itself:
 *      two `hover:bg-*` in one list are one tailwind-merge group, so the later
 *      (selected) one replaces the base hover rather than losing to it.
 *
 * The full-alpha 2px inset ring is what actually carries the state — it reads at
 * ~7:1 on white and, unlike a fill, does not compete with the solid event chips
 * inside the cell. `aria-pressed` on the cell keeps the state available to
 * assistive tech either way; this is only about seeing it.
 */
export const DAY_CELL_BASE =
  'flex flex-col items-stretch gap-1 border-b border-r border-border/[0.09] bg-surface px-1 pb-1 pt-1 text-left transition hover:bg-foreground/[0.035]';

export const SELECTED_DAY_CELL =
  'bg-primary/[0.10] ring-2 ring-inset ring-primary hover:bg-primary/[0.14]';

/**
 * The day number's pill. `today` keeps the solid fill (Google's convention) and
 * the selected day is marked by the cell ring above, so the two read as
 * different things when they are different days and simply coincide when they
 * are the same one.
 */
export const DAY_NUMBER_BASE =
  'inline-flex h-[21px] min-w-[21px] items-center justify-center rounded-full px-1 text-[11px] font-semibold tabular-nums leading-none';
