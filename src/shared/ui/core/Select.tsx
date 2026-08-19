import { forwardRef, type SelectHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';
import { CONTROL_BASE, CONTROL_HEIGHT } from './controlStyles';

export type SelectProps = SelectHTMLAttributes<HTMLSelectElement>;

// Matches the demo `.fi` select. Shares CONTROL_BASE/CONTROL_HEIGHT with
// <Input> so the two are exactly the same height and inset wherever they sit in
// the same row — see controlStyles.ts.
export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, children, ...props }, ref) => (
    <select
      ref={ref}
      className={cn(CONTROL_BASE, CONTROL_HEIGHT, className)}
      {...props}
    >
      {children}
    </select>
  ),
);
Select.displayName = 'Select';
