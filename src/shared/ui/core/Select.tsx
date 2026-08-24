import { forwardRef, type SelectHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';
import { CONTROL_BASE, CONTROL_HEIGHT } from './controlStyles';

export type SelectProps = SelectHTMLAttributes<HTMLSelectElement>;

/**
 * Matches the demo `.fi` select. Shares CONTROL_BASE/CONTROL_HEIGHT with
 * <Input> so the two are exactly the same height and inset wherever they sit in
 * the same row — see controlStyles.ts.
 *
 * `control-chevron` (index.css) is what makes it the same DROPDOWN as the other
 * two. This was a bare <select>, so it painted the operating system's arrow,
 * while <ListboxSelect> and <StatusSelect> both draw a lucide ChevronDown
 * themselves. Every list page's filter bar therefore showed a platform arrow on
 * its status filter and a lucide chevron on its row-level status badge — two
 * glyphs, two sizes, two insets, for one control.
 *
 * `pr-9` is the room that chevron needs. CONTROL_BASE's `px-3.5` applies to both
 * sides, and a 14px glyph inset 14px from the right edge occupies the last 28px
 * — so with only 14px reserved a long option label ran underneath the arrow.
 */
export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, children, ...props }, ref) => (
    <select
      ref={ref}
      /**
       * Browser autofill OFF by default, for every dropdown in the app.
       *
       * A `<select>` here always holds an APP-DOMAIN enum — a lead stage, an
       * urgency, a care level, a status filter — and a browser profile has no
       * correct value for any of them. It writes into them anyway: given no
       * `autocomplete` token, Chrome classifies a form by heuristic, and a form
       * that holds a name, a phone and an email reads to it as an address form,
       * at which point profile heuristics are applied to every control in it,
       * selects included. That is the "Stage is changed by autofill in the Leads
       * pipeline" report — nothing in the app touched Stage; the browser did.
       *
       * Set HERE, on the primitive, and not only in EntityFormModal, because the
       * entity forms are not the only forms: roughly thirty hand-rolled modals
       * build their own field rows out of this component and would each have had
       * to remember the attribute. The one native-select-shaped field a browser
       * could legitimately fill is a country/state picker, and the app's only
       * such field (onboarding's State) is a <ListboxSelect> — a custom listbox
       * that is not a form control at all, so nothing loses a useful autofill.
       *
       * Before `{...props}`, so a caller that genuinely wants a token (e.g.
       * `autoComplete="address-level1"`) still overrides it.
       */
      autoComplete="off"
      className={cn(CONTROL_BASE, CONTROL_HEIGHT, 'control-chevron pr-9', className)}
      {...props}
    >
      {children}
    </select>
  ),
);
Select.displayName = 'Select';
