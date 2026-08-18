import { forwardRef, type InputHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';

export type InputProps = InputHTMLAttributes<HTMLInputElement>;

// Mirrors wemarketplus-site `.field input`: #0a1628 bg, 1px white/.12 border,
// 10px radius, 11px/14px padding, 14px text, accent border on focus,
// #3a4d6b placeholder.
export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, type = 'text', ...props }, ref) => (
    <input
      ref={ref}
      type={type}
      className={cn(
        'w-full rounded-[10px] border border-border/[0.12] bg-surface-raised px-3.5 py-[11px] text-[14px] text-foreground outline-none transition-colors duration-150',
        'placeholder:text-faint',
        'focus:border-primary',
        'disabled:cursor-not-allowed disabled:opacity-50',
        // date/time inputs stand 2px taller than every field beside them, which
        // is visible the moment one shares a row with a text input (Mileage's
        // Date next to From/To, the appointment modal's Starts/Ends next to
        // Type). The cause is WebKit's `::-webkit-datetime-edit`, whose
        // intrinsic block size is 23px against this input's 21px line box —
        // NOT padding, and not `line-height`, which the shadow part ignores.
        // Pinning the part to the same line box makes a date field exactly as
        // tall as a text field. Matches nothing on other input types, so it is
        // applied unconditionally rather than behind a list of type names.
        '[&::-webkit-datetime-edit]:h-[21px]',
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = 'Input';
