import { forwardRef, type LabelHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';

export interface LabelProps extends LabelHTMLAttributes<HTMLLabelElement> {
  /**
   * Appends the conventional `*`.
   *
   * Lives here rather than at each call site because the app already had one
   * spelling of this marker — inline in EntityFormModal, for its `field.required`
   * descriptors — and the ~30 HAND-ROLLED modals that build their own field rows
   * (the tour form, the calendar's schedule form, the appointment forms) had no
   * way to reach it, so none of them marked anything. That is the "mandatory
   * fields are not marked" report: not a missing rule, a marker only half the
   * forms could use.
   *
   * Mark exactly the fields the schema really requires. A `*` on a field the API
   * accepts empty is worse than no `*` at all, and a field that is
   * schema-required but structurally un-blankable (a <Select> with no empty
   * option, pre-filled) is noise rather than information.
   */
  required?: boolean;
}

// Mirrors wemarketplus-site `.field label`: 12px, weight 700, #8b9fc4,
// uppercase, letter-spacing .04em, 6px bottom margin.
export const Label = forwardRef<HTMLLabelElement, LabelProps>(
  ({ className, required, children, ...props }, ref) => (
    <label
      ref={ref}
      className={cn(
        'mb-1.5 block text-[12px] font-bold uppercase tracking-label text-muted-soft',
        className,
      )}
      {...props}
    >
      {children}
      {required && (
        // The destructive tone so it reads as a requirement rather than
        // decoration. `aria-hidden` because the requirement is announced by
        // `aria-required` on the CONTROL — without it a screen reader says
        // "star" after every mandatory label. `title` gives a sighted user who
        // does not know the convention the same explanation.
        <span aria-hidden="true" title="Required" className="ml-0.5 text-destructive">
          *
        </span>
      )}
    </label>
  ),
);
Label.displayName = 'Label';
