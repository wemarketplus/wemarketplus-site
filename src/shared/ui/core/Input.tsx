import { forwardRef, type InputHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';
import { CONTROL_BASE, CONTROL_HEIGHT } from './controlStyles';

export type InputProps = InputHTMLAttributes<HTMLInputElement>;

// Mirrors wemarketplus-site `.field input`: #0a1628 bg, 1px white/.12 border,
// 10px radius, 14px text, accent border on focus, #3a4d6b placeholder.
// Height and horizontal padding come from CONTROL_BASE so an <Input> and the
// <Select> beside it are the same object — see controlStyles.ts.
export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className, type = 'text', ...props }, ref) => (
    <input
      ref={ref}
      type={type}
      className={cn(
        CONTROL_BASE,
        CONTROL_HEIGHT,
        'placeholder:text-faint',
        // date/time inputs stand taller than every field beside them, which is
        // visible the moment one shares a row with a text input (Mileage's Date
        // next to From/To, the appointment modal's Starts/Ends next to Type).
        // The cause is WebKit's `::-webkit-datetime-edit`, whose intrinsic
        // block size is 23px against this input's 21px line box — NOT padding,
        // and not `line-height`, which the shadow part ignores. Pinning the
        // part to the same line box keeps the control's own height authoritative
        // instead of the shadow DOM stretching it. Matches nothing on other
        // input types, so it is applied unconditionally rather than behind a
        // list of type names.
        '[&::-webkit-datetime-edit]:h-[21px]',
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = 'Input';
