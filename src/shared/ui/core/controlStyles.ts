/**
 * The one form-control geometry: height, radius, border, surface and type.
 *
 * <Input> and <Select> previously each carried their own padding — `py-[11px]`
 * against `py-[10px]` — with no explicit height, so their real heights came out
 * of two different intrinsic line boxes and landed ~2px apart. Side by side in
 * a filter bar or a two-column form row (the tour modal's Status next to
 * Duration, every list page's search next to its status filter) that reads as
 * one control sagging below the other.
 *
 * Pinning an explicit height rather than tuning padding is what makes it hold:
 * padding only produces a matching height while both controls happen to have
 * matching line boxes, which a select, a date input and a text input do not.
 *
 * 44px (h-11) is deliberately the SAME as the Button `md` size, so a form's
 * fields and its submit button share a height too.
 */
export const CONTROL_HEIGHT = 'h-11';

export const CONTROL_BASE =
  'w-full rounded-md border border-border/[0.12] bg-surface-raised px-3.5 text-[14px] text-foreground outline-none transition-colors duration-150 focus:border-primary disabled:cursor-not-allowed disabled:opacity-50';

/**
 * The inset of an icon rendered INSIDE a control, and the padding its field
 * must reserve for it.
 *
 * These two are a pair: the icon is 16px (`h-4 w-4`) at a 12px inset, so it
 * ends at 28px and the text has to start after that. Kept together because they
 * were previously restated at each call site — `left-3` here, `pl-9` there —
 * and a field that reserved the wrong amount either crowded the glyph or left a
 * gap twice as wide as the inset.
 */
export const CONTROL_ICON_INSET = 'left-3';
export const CONTROL_ICON_PADDING = 'pl-9';

/**
 * ── The topbar's control geometry ─────────────────────────────────────────────
 *
 * Every control in DashboardHeader is 36px tall and wears the SAME hairline and
 * surface. The heights were already aligned; the BORDERS were not. The search
 * pill, the product switcher and the profile chip each carried their own copy of
 * `border border-border/[0.08] bg-surface/60`, while the notifications bell and
 * the sign-out button were `ghost` Buttons — no border, no surface at all.
 *
 * That is what "not visually balanced" was describing. Reading the row left to
 * right you got: bordered pill, bordered pill, BARE ICON, bordered pill, BARE
 * TEXT. Four of the five controls announced their own hit area and one in the
 * middle of them did not, so the bell read as a stray glyph dropped between two
 * chips rather than as one of five peers — and the search field's hairline
 * looked like a different weight from the fields on the page below simply
 * because nothing near it agreed with it either.
 *
 * `HEADER_CONTROL` is now the single source for that hairline+surface, so a
 * fourth control added to the row cannot introduce a fifth spelling of it.
 */
export const HEADER_CONTROL_HEIGHT = 'h-9';

export const HEADER_CONTROL_BASE =
  'rounded-pill border border-border/[0.08] bg-surface/60 transition-colors hover:border-border/[0.16]';
