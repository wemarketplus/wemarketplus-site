import { ChevronDown } from 'lucide-react';
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
 * A native <select> on purpose — keyboard-operable, screen-reader announced, and
 * it uses the platform picker on touch devices, none of which a div-based menu
 * gives for free. The <select> renders the matching option's own text, so the
 * visible label cannot drift from the stored value.
 *
 * Colour and geometry are imported from Pill rather than restated, so a status
 * badge and an editable status badge are the same object.
 *
 * ── The DEAD ZONE this also fixes ─────────────────────────────────────────────
 * The pill's padding used to live on the wrapper <span>, so the <select> was
 * inset INSIDE it and only covered part of the badge: measured in the leads
 * pipeline, an 80x11px select inside a 114x22px pill — 35% of what looks like
 * one control was live, and the other 65% belonged to a <span> that does
 * nothing. `elementFromPoint` on the chevron returned the SPAN.
 *
 * The chevron is the worst of it. It is the universal "this opens" affordance,
 * it is `pointer-events-none`, and it sat over the wrapper — so clicking the
 * one part of the badge that advertises a dropdown neither opened it nor even
 * focused it. Nothing was mis-selected by those clicks (the value and the
 * network stayed put, which is what the "clicking empty space selects a status"
 * report feared); they were simply swallowed, which reads as the control
 * randomly ignoring you.
 *
 * So the PADDING moves onto the <select>. The wrapper then shrink-wraps it and
 * every pixel of the badge — chevron included — is the select's own hit box,
 * with the chevron's `pointer-events-none` now passing clicks down to it rather
 * than to an inert span.
 */
export function StatusSelect({
  value,
  tone,
  options,
  disabled,
  onChange,
  'aria-label': ariaLabel,
}: StatusSelectProps) {
  return (
    // The TONE lives on the wrapper, not the <select>: the chevron is a sibling
    // of the select, so it can only pick up the tone's text colour by
    // inheritance. The select is transparent and inherits font + colour from
    // here (Tailwind's preflight makes form controls inherit both).
    <span
      className={cn(
        PILL_SHAPE,
        PILL_TONES[tone ?? 'b'],
        // `p-0` hands PILL_SHAPE's px-2.5 to the <select>; `items-stretch`
        // then makes the select fill the 22px height instead of sitting on
        // the centre line as an 11px band.
        'relative items-stretch p-0',
        disabled && 'opacity-60',
      )}
    >
      <select
        value={value}
        disabled={disabled}
        aria-label={ariaLabel}
        onChange={(e) => onChange(e.target.value)}
        className={cn(
          // pl-2.5 is PILL_SHAPE's own inline padding; pr-6 is the gutter the
          // chevron is positioned into. Both belong to the select now, so the
          // badge has no border it does not own.
          'cursor-pointer appearance-none rounded-pill bg-transparent pl-2.5 pr-6 outline-none',
          'focus-visible:ring-2 focus-visible:ring-primary/50',
          'disabled:cursor-not-allowed',
        )}
      >
        {/*
          The OPTIONS are rendered by the platform, on its own surface — they
          cannot carry the pill's pastel fill, and forcing colours onto them is
          unreliable across browsers. The list stays plain text; the colour lives
          on the closed control, which is the part read when scanning a column.
        */}
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      {/* Decorative — the <select> already announces itself and its value. */}
      <ChevronDown
        aria-hidden="true"
        className="pointer-events-none absolute right-1.5 top-1/2 h-3 w-3 -translate-y-1/2 opacity-70"
      />
    </span>
  );
}
