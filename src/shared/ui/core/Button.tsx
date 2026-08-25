import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/shared/utils/cn';

// Mirrors wemarketplus-site `.btn-login` / `.btn-main`: pill-shaped, primary
// accent fill with dark text, hover via opacity .88. The accent is
// `--color-primary` so a [data-product] scope recolors it (azure ↔ amber).
// The marketing site draws these at weight 800; in the app they are 700 — see
// the note below for why that one property deliberately does not mirror.
//
// WEIGHT IS PER-VARIANT, not shared. `font-extrabold` used to sit in the base
// string below, so the 800 that belongs to the site's primary CTA was also
// worn by every Cancel, every ghost icon button and every quiet secondary —
// 104 of them against 145 real CTAs. Two buttons side by side in a dialog
// footer then shouted equally loudly and the footer had no primary action, only
// two of them: the "Cancel and Confirm should not both appear excessively bold"
// report. The affordance the fill and the border already encode does not also
// need the weight, so the quiet variants step down to 600.
//
// THE FILLED VARIANTS ARE 700, NOT 800, and that half of the same report went
// unfixed the first time round. Stepping only the quiet variants down closed the
// gap from the wrong end: the footer went from 800-vs-800 to 800-vs-600, so the
// filled action still shouted on its own and the SAME complaint came back twice
// more — "Save Changes text is excessively bold" on My Profile, "Cancel and
// Confirm Changes are excessively bold" in the plan-switch popup. 800 is a
// display weight; on a 14px label inside a solid pill it renders heavier than
// anything else on the page, the h1 included. 700 against 600 still reads as the
// louder of the two, and the FILL is what actually marks the primary action —
// the weight only has to agree with it, not carry it alone.
//
// `whitespace-nowrap` is STRUCTURAL, not typographic. Every size below pins an
// explicit height (h-9/h-11/h-12), so a label that wraps does not make its
// button taller — it spills the second line straight out of the pill. That is
// what broke the referral-partners table: "Log visit" in a w-44 actions cell
// wrapped to "Log" / "visit" and the second word rendered outside the border,
// under an icon that had been pushed off its own centre line. A button is a
// single-line object at a fixed height; the label must not be the one thing
// that can violate that. `size: block` opts back out — it is the only size with
// no fixed height (auth submits), so wrapping there is safe.
const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 whitespace-nowrap [&>svg]:shrink-0 transition-opacity duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 disabled:cursor-not-allowed disabled:opacity-50',
  {
    variants: {
      variant: {
        // .btn-login / .btn-main — solid accent pill, dark text
        primary:
          'rounded-pill bg-primary font-bold text-primary-foreground hover:opacity-[0.88]',
        // reset-password.html gradient. Retuned for the light theme: the old
        // #49b6ff→#8cff66 ramp was a dark-canvas accent and washed out on white.
        gradient:
          'rounded-pill font-bold text-primary-foreground hover:opacity-[0.88] bg-[linear-gradient(90deg,#0f5c44,#16805c)]',
        /**
         * THE QUIET VARIANTS' BORDER IS 50% α, NOT 12/14%.
         *
         * These two are the app's "visible but not shouting" buttons, and the
         * only thing marking their hit area is that hairline — they carry no
         * fill worth the name (`surface-raised` is #fafbfa, which is 1.02:1
         * against a white card, i.e. nothing). At 12% α the border blended to
         * #e2e5e4 over white: 1.29:1, against the 3:1 WCAG 1.4.11 asks of a
         * control boundary. So a dialog footer's Cancel was, in practice, dark
         * text floating next to a solid green pill with no button around it —
         * the "Cancel button has insufficient contrast/visibility" report, and
         * the reason the Mileage "Add link" action read as a caption.
         *
         * 50% is the LOWEST α that clears the floor: it blends to #888f8c
         * (3.30:1 on white) where 45% gives 2.85:1. It is a token alpha, not a
         * new colour, so `--color-border` flipping to white in the dark theme
         * keeps it correct there (≈5.3:1 on #0d0f15) with no second rule.
         *
         * Note this was ALSO the bug in the old hover: `hover:border-border/25`
         * was below the new rest state, so hovering made the button fainter.
         */
        // subtle filled secondary used across the site
        secondary:
          'rounded-pill border border-border/50 bg-surface-raised font-semibold text-foreground hover:border-border/70',
        outline:
          'rounded-pill border border-border/50 bg-transparent font-semibold text-foreground hover:border-border/70 hover:bg-foreground/[0.05]',
        ghost:
          'rounded-pill bg-transparent font-semibold text-muted hover:text-foreground hover:bg-foreground/[0.05]',
        destructive:
          'rounded-pill bg-destructive font-bold text-destructive-foreground hover:opacity-[0.88]',
        link: 'bg-transparent font-semibold text-primary hover:underline underline-offset-4',
      },
      size: {
        sm: 'h-9 px-4 text-[13px]',
        md: 'h-11 px-5 text-[14px]',
        lg: 'h-12 px-6 text-[15px]',
        block: 'w-full whitespace-normal py-[13px] text-[15px]',
        icon: 'h-9 w-9',
        square: 'h-9 w-9 rounded-md',
      },
    },
    defaultVariants: { variant: 'primary', size: 'md' },
  },
);

export interface ButtonProps
  extends ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, type = 'button', ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn(buttonVariants({ variant, size }), className)}
      {...props}
    />
  ),
);
Button.displayName = 'Button';
