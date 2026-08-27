import { useId } from 'react';
import { ListboxSelect } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { PILL_SHAPE, PILL_TONES, type PillProps } from './Pill';

export interface StatusSelectOption {
  value: string;
  label: string;
}

interface StatusSelectProps {
  value: string;
  tone: PillProps['tone'];
  options: readonly StatusSelectOption[];
  disabled?: boolean;
  onChange: (value: string) => void;
  /** Announced to screen readers — name the row, e.g. "Change status for Ada Lovelace". */
  'aria-label': string;
}

/**
 * The panel needs to fit "Not applicable" / "Needs attention" at the option
 * list's own 14px, and the closed pill is only as wide as its current label —
 * so the list gets a floor rather than the badge's width.
 */
const PANEL_MIN_WIDTH = 168;

/**
 * The option list, at BADGE scale rather than field scale.
 *
 * ── The bug this fixes ────────────────────────────────────────────────────────
 * The closed control is a 22px pill, and it was correct. The OPEN list was not:
 * it kept ListboxSelect's field geometry — 14px type at 8px/14px padding, so a
 * 37px row — and ListboxSelect's 264px ceiling, which is sized for the 51-state
 * list that component was built for.
 *
 * On Apartment inventory that came out as a 264px panel hanging off a 22px
 * badge, with a scrollbar, for SEVEN statuses: 7 x 37 + 8 = 267px of content
 * against a 264px cap, so the list was clipped and scrollable by three pixels.
 * A dropdown ten times the height of the control that opened it, scrolling to
 * reveal nothing, is the "excessive height / occupies unnecessary space" report.
 *
 * 12px type at 5px/12px padding gives a ~30px row, in proportion to the 11px
 * badge, and the taller ceiling means a status list of up to ten options — the
 * longest of the eight consumers is the nine-stage lead pipeline — opens in full
 * with no scrollbar at all. A longer list than that still caps, which is the
 * whole point of not being a native popup.
 */
const OPTION_CLASS = 'px-3 py-[5px] text-[12px]';
const PANEL_MAX_HEIGHT = 320;

/**
 * A row's status: ONE control that both reports the current value and changes it.
 *
 * ── The bug this fixes ────────────────────────────────────────────────────────
 * Six list tables rendered status as a coloured <Pill> AND, immediately beside
 * it, a native <select> bound to the same field. Both were populated from the
 * same value, so every row stated its status twice — the tour scheduler's
 * "Status appears multiple times". Worse than redundant: two controls that look
 * different (a filled badge, a bordered dropdown) invite the reading that they
 * are two different fields, and the second one silently wrote to the record on
 * change while the first only looked like a label.
 *
 * Deleting the dropdown would have removed real behaviour — changing a status
 * from the list without opening the edit modal is a genuine shortcut, wired to a
 * live PATCH. Deleting the pill would have cost the colour that makes a column
 * of statuses scannable. So neither is dropped: the badge IS the dropdown.
 *
 * Colour and geometry are imported from Pill rather than restated, so a status
 * badge and an editable status badge are the same object.
 *
 * ── WHY THIS IS NO LONGER A NATIVE <select> ───────────────────────────────────
 * It was one, on the reasoning that the platform picker is keyboard-operable,
 * screen-reader announced and the right control on touch, for free. All true —
 * and all of it also came with a popup the page does not own, which is the half
 * that could not stay.
 *
 * A native popup decides for itself which of its pixels commit a value, and its
 * blank regions — the list's padding, the scroll gutter, the strip under the
 * last row — commit whatever is HIGHLIGHTED on mouse-up. That produced the
 * report "opening the Fee Status dropdown, moving through the options and then
 * clicking an empty area selects a fee status". On a form field that would be
 * cosmetic. Here it is not: every `change` on this control is wired straight to
 * a PATCH (see the eight consumers — leads, tasks, tours, the four operations
 * boards, paid referrals), so a stray commit is a silent, un-undoable write to
 * the record. No CSS or JS in the page can reach that popup to prevent it; the
 * only fix is to stop the browser drawing it.
 *
 * A second defect closed by the same move: a native <select> is a form control,
 * so Chrome's profile heuristics would fill it. This one carried no
 * `autoComplete="off"` — the guard `Select` has borne since the "Stage changed
 * on its own during an autofill" report — and, sitting in a table that is not
 * inside any <form>, it was exactly the unowned control that heuristic writes
 * to. One autofill then meant one PATCH and one "…updated" toast PER ROW, which
 * is the "multiple Update popups after 2-3 referrals" report. A <button> is not
 * a form control, so there is now nothing here for autofill to write to.
 *
 * What replaces it is NOT a hand-rolled menu: it delegates to <ListboxSelect>,
 * which already implements the full listbox pattern (roving Arrow/Home/End with
 * `aria-activedescendant`, Enter/Space to commit, Escape to cancel, type-ahead,
 * a real `role="combobox"` trigger) and — the point of the exercise — commits
 * ONLY from an option's own pointerdown, with the panel's padding belonging to a
 * <ul> that has no handler. Blank space is inert by construction. This component
 * keeps its own name, props and pill geometry, so all eight call sites are
 * unchanged.
 */
export function StatusSelect({
  value,
  tone,
  options,
  disabled,
  onChange,
  'aria-label': ariaLabel,
}: StatusSelectProps) {
  // The listbox needs a stable id to point `aria-activedescendant` at its
  // options, and a status badge has no <Label> to borrow one from.
  const id = useId();

  return (
    <ListboxSelect
      id={id}
      value={value}
      onChange={onChange}
      options={options}
      disabled={disabled}
      aria-label={ariaLabel}
      minPanelWidth={PANEL_MIN_WIDTH}
      optionClassName={OPTION_CLASS}
      maxPanelHeight={PANEL_MAX_HEIGHT}
      // 12px glyph, and it inherits the tone's text colour instead of the
      // field-sized chevron's `text-muted` — the badge is one colour object.
      chevronClassName="h-3 w-3 text-current opacity-70"
      className={cn(
        PILL_SHAPE,
        PILL_TONES[tone ?? 'b'],
        // The pill SHRINK-WRAPS and carries no border: both undo a piece of the
        // shared field geometry ListboxSelect's trigger starts from (`w-full`,
        // a hairline) that a badge must not wear. `gap-1` closes the 8px field
        // gap to something a 22px pill can hold.
        'w-auto gap-1 border-0',
        // The pill has no border to recolour on focus, so it needs the ring the
        // bordered field variant does without.
        'focus-visible:ring-2 focus-visible:ring-primary/50',
        disabled && 'opacity-60',
      )}
    />
  );
}
