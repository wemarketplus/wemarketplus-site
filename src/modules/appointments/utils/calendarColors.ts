/**
 * A per-user colour for the shared "All users" calendar.
 *
 * STORED FIRST, DERIVED AS A FALLBACK. This function used to derive the colour
 * from a hash of the user id alone, and said that if the product ever wanted
 * chosen colours, this is where a stored value would be read instead. That is
 * now what happens: `users.calendarColor` holds the `#rrggbb` a user picked in
 * their profile settings, and `calendarColorFor` prefers it whenever it is
 * present.
 *
 * The hash did NOT go away, and deleting it would be a mistake. The column is
 * nullable and nothing was backfilled, so "no choice made" is the state most
 * users are in and will stay in — the hash is what keeps them distinguishable
 * without anyone having to visit a settings page. It is also the answer for an
 * id whose stored colour is a hex from a palette we no longer ship: unknown
 * values fall through to derivation rather than rendering nothing.
 *
 * The trade-off that remains: two users can still land on the same swatch, now
 * by choosing it rather than by hash collision. That is accepted deliberately —
 * the alternative is a uniqueness rule that has to tell the ninth person on a
 * team of eight colours that they may not have a colour at all. Colour is a hint
 * for telling reps apart, not an identifier, and it must never carry meaning
 * (a status, a priority) that a collision could corrupt.
 */

export interface CalendarColor {
  /** Tailwind background class for the swatch/dot. */
  dot: string;
  /** Tailwind text class, for a legend label. */
  text: string;
}

/**
 * The choosable identity hues, and the ONLY values the backend accepts for
 * `calendarColor` (mirrored in wemarketplus-backend/src/users/users.constants.ts
 * as CALENDAR_PALETTE_HEXES — keep the two in step).
 *
 * Deliberately not the brand palette's semantic tones (success / destructive /
 * warning): a rep's colour must not read as "this visit went well" or "this one
 * is a problem". These are identity hues only.
 *
 * `hex` is the durable, storable fact; `dot`/`text` are the Tailwind classes the
 * UI renders. They are written out in full rather than interpolated from `hex`
 * because Tailwind's compiler only emits arbitrary-value classes it can see as
 * complete literals in the source — a template string would produce class names
 * that silently have no CSS.
 */
export const CALENDAR_PALETTE = [
  { hex: '#3b82f6', label: 'Blue', dot: 'bg-[#3b82f6]', text: 'text-[#3b82f6]' },
  { hex: '#8b5cf6', label: 'Violet', dot: 'bg-[#8b5cf6]', text: 'text-[#8b5cf6]' },
  { hex: '#ec4899', label: 'Pink', dot: 'bg-[#ec4899]', text: 'text-[#ec4899]' },
  { hex: '#14b8a6', label: 'Teal', dot: 'bg-[#14b8a6]', text: 'text-[#14b8a6]' },
  { hex: '#f59e0b', label: 'Amber', dot: 'bg-[#f59e0b]', text: 'text-[#f59e0b]' },
  { hex: '#6366f1', label: 'Indigo', dot: 'bg-[#6366f1]', text: 'text-[#6366f1]' },
  { hex: '#06b6d4', label: 'Cyan', dot: 'bg-[#06b6d4]', text: 'text-[#06b6d4]' },
  { hex: '#a855f7', label: 'Purple', dot: 'bg-[#a855f7]', text: 'text-[#a855f7]' },
] as const;

export type CalendarPaletteEntry = (typeof CALENDAR_PALETTE)[number];

/** Unassigned work is grey — absence of an owner, not another owner. */
const UNASSIGNED: CalendarColor = {
  dot: 'bg-foreground/25',
  text: 'text-muted-soft',
};

/**
 * FNV-1a, chosen because it is tiny and stable across runs and machines. The
 * colour must not change between a page load and a refresh, which rules out
 * anything seeded by insertion order or `Math.random`.
 */
const hash = (value: string): number => {
  let h = 0x811c9dc5;
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return h >>> 0;
};

/** The palette entry for a stored hex, or undefined if it is not one of ours. */
export function paletteEntryForHex(
  hex: string | null | undefined,
): CalendarPaletteEntry | undefined {
  if (!hex) return undefined;
  return CALENDAR_PALETTE.find((entry) => entry.hex === hex);
}

/**
 * The colour to paint a user's calendar rows in.
 *
 * `storedColor` is the `#rrggbb` from their profile (users.calendarColor) and is
 * OPTIONAL: every existing caller that passes only a user id keeps its previous
 * behaviour exactly, which is why the stored value was added as a second
 * argument rather than by changing the parameter's shape.
 */
export function calendarColorFor(
  userId: string | null | undefined,
  storedColor?: string | null,
): CalendarColor {
  if (!userId) return UNASSIGNED;
  // An unrecognised hex (a retired palette entry) is treated as no choice at
  // all, so the row still gets a stable colour instead of an empty class.
  return (
    paletteEntryForHex(storedColor) ??
    CALENDAR_PALETTE[hash(userId) % CALENDAR_PALETTE.length]
  );
}
