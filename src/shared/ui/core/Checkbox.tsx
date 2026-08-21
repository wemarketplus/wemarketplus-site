import { forwardRef, type CSSProperties, type InputHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';

/**
 * The one checkbox.
 *
 * WHY THIS EXISTS. Every checkbox in the app was a bare `<input type="checkbox">`
 * carrying `accent-[rgb(var(--color-primary))]` (or `accent-primary`), which asks
 * the BROWSER to paint the control. Three things follow from that, and all three
 * were reported as "the contact checkbox turns black when selected":
 *
 *  - `accent-color` only tints a native widget; the `rounded`, `border-border/25`
 *    and `text-primary` classes sitting beside it on those inputs did nothing at
 *    all. So the checked state was a hard-edged 14px native square filled with
 *    the deep green primary (#0f5c44) — at that size, under the browser's own
 *    shading, indistinguishable from black.
 *  - It rendered differently per engine, which is why the same screen can look
 *    fine in one browser and black in another.
 *  - There was no focus ring of the app's own, so keyboard focus was whatever
 *    the platform happened to draw.
 *
 * This owns the whole control instead: `appearance-none` for the box, an inline
 * SVG tick applied ONLY in the checked state, and the app's tokens for every
 * colour. That checked state is `bg-primary` with a white tick — deliberately the
 * same pairing the shared Switch uses for "on", so the design system's two
 * selection controls agree. What turns the reading from "black square" into
 * "green checkbox" is the geometry the native widget refused: a 16px box, a 4px
 * radius, a hairline border, and a real tick with room around it.
 *
 * Contrast (light palette, WCAG 2.1 SC 1.4.11, 3:1 floor for non-text):
 *   unchecked border `border-border/50` → 3.29:1 against the white card
 *   checked  fill   `bg-primary`        → 7.97:1 against the card
 *   white tick on that fill             → 7.97:1
 * State is never colour alone (SC 1.4.1): the tick is a shape, and this is still
 * a real `<input type="checkbox">`, so `:checked` reaches assistive tech
 * unchanged and every existing `onChange`/`checked` call site keeps working.
 */

// The tick and the indeterminate dash, as data URIs. An <input> can have no
// children, so the mark has to be a background image; these are passed through
// CSS custom properties because a `var()` cannot be interpolated into a
// background-image inside a class name, and an inline data URI in a Tailwind
// arbitrary value is unreadable.
//
// `stroke='white'` is a literal rather than a token: the mark is only ever drawn
// on the primary fill, where white IS the paired colour (`--color-primary-
// foreground` is 255 255 255 in both palettes), and a var() cannot cross into the
// SVG's own document.
const TICK =
  "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='white' stroke-width='2.5' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3.5 8.5l3 3 6-6'/%3E%3C/svg%3E\")";
const DASH =
  "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16' fill='none' stroke='white' stroke-width='2.5' stroke-linecap='round'%3E%3Cpath d='M4 8h8'/%3E%3C/svg%3E\")";

const MARK_VARS = {
  '--wm-check': TICK,
  '--wm-dash': DASH,
} as CSSProperties;

export type CheckboxProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'type'>;

export const Checkbox = forwardRef<HTMLInputElement, CheckboxProps>(
  ({ className, style, ...props }, ref) => (
    <input
      ref={ref}
      type="checkbox"
      className={cn(
        // The box. `shrink-0` because these sit in flex rows beside labels that
        // wrap, and a squashed checkbox is its own bug.
        'h-4 w-4 shrink-0 cursor-pointer appearance-none rounded-[4px] border transition-colors',
        'border-border/50 bg-surface-raised hover:border-border/70',
        'bg-center bg-no-repeat',
        // Checked: filled, border matched to the fill, tick painted on top.
        'checked:border-primary checked:bg-primary',
        'checked:bg-[image:var(--wm-check)] checked:bg-[length:14px_14px]',
        // Indeterminate — DataTable's "some rows on this page are selected"
        // header. Same fill with a dash, so a partial selection is never read as
        // a complete one.
        'indeterminate:border-primary indeterminate:bg-primary',
        'indeterminate:bg-[image:var(--wm-dash)] indeterminate:bg-[length:14px_14px]',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
        'disabled:cursor-not-allowed disabled:opacity-50',
        className,
      )}
      // Caller style last, so a consumer can still override.
      style={{ ...MARK_VARS, ...style }}
      {...props}
    />
  ),
);
Checkbox.displayName = 'Checkbox';
