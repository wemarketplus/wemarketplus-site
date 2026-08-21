import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';

/**
 * The one on/off switch.
 *
 * Two hand-rolled copies of this control existed (notification preferences and
 * the feature-flag admin list), both written against the OLD dark canvas and
 * never retuned when the signed-in app flipped to the light palette. On white
 * the off state was effectively invisible: a `foreground/6%` track (1.16:1 vs
 * the page), a `border/12%` hairline (1.27:1 — no discernible boundary) and,
 * worst of all, a hard-coded `bg-white` thumb sitting on that near-white track.
 * The thumb IS the state indicator, so "off" rendered as a blank smudge.
 *
 * Every colour here is a token rather than a literal, which is what makes the
 * control survive a palette change: the same markup reads correctly inside the
 * dark `.marketing-root` scope, where `foreground`/`border`/`primary-foreground`
 * all invert. The old `bg-white` thumb could not.
 *
 * Contrast (light palette, WCAG 2.1 SC 1.4.11 Non-text Contrast, 3:1 floor):
 *   off track boundary `border-border/50` → 3.29:1 against the white page
 *   off thumb `bg-muted` on the off track  → 4.21:1
 *   on  track `bg-primary`                 → 7.97:1 against the page
 *   on  thumb `bg-primary-foreground`      → 7.97:1 on the primary track
 * Both hover states only increase separation (6.24:1 / 10.26:1 track vs page).
 *
 * State is never carried by colour alone (SC 1.4.1): the thumb also travels
 * left→right, and `role="switch"` + `aria-checked` expose it to assistive tech.
 */
export interface SwitchProps
  extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'onChange' | 'value'> {
  checked: boolean;
  onCheckedChange: (next: boolean) => void;
}

export const Switch = forwardRef<HTMLButtonElement, SwitchProps>(
  ({ checked, onCheckedChange, className, disabled, ...props }, ref) => (
    <button
      ref={ref}
      type="button"
      role="switch"
      aria-checked={checked}
      disabled={disabled}
      onClick={() => onCheckedChange(!checked)}
      className={cn(
        'relative inline-flex h-6 w-11 shrink-0 items-center rounded-pill border transition-colors duration-150',
        // Offset is required, not decorative: without it a primary/50 ring drawn
        // flush against the ON state's primary track is invisible.
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 focus-visible:ring-offset-2 focus-visible:ring-offset-bg',
        'disabled:cursor-not-allowed disabled:opacity-50',
        checked
          ? 'border-primary bg-primary hover:bg-primary-hover hover:border-primary-hover'
          : 'border-border/50 bg-foreground/[0.08] hover:border-border/70 hover:bg-foreground/[0.14]',
        className,
      )}
      {...props}
    >
      <span
        className={cn(
          'pointer-events-none inline-block h-4 w-4 transform rounded-full transition-transform duration-150',
          checked
            ? 'translate-x-6 bg-primary-foreground'
            : 'translate-x-1 bg-muted',
        )}
      />
    </button>
  ),
);
Switch.displayName = 'Switch';
