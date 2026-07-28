import { forwardRef, type SelectHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';

export type SelectProps = SelectHTMLAttributes<HTMLSelectElement>;

// Matches the demo `.fi` select: dark surface, 10px radius, accent focus.
export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ className, children, ...props }, ref) => (
    <select
      ref={ref}
      className={cn(
        'w-full rounded-[10px] border border-border/[0.12] bg-surface-raised px-3 py-[10px] text-[14px] text-foreground outline-none transition-colors focus:border-primary disabled:opacity-50',
        className,
      )}
      {...props}
    >
      {children}
    </select>
  ),
);
Select.displayName = 'Select';
