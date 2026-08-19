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
  'w-full rounded-[10px] border border-border/[0.12] bg-surface-raised px-3.5 text-[14px] text-foreground outline-none transition-colors duration-150 focus:border-primary disabled:cursor-not-allowed disabled:opacity-50';
