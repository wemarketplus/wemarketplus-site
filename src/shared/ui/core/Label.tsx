import { forwardRef, type LabelHTMLAttributes } from 'react';
import { cn } from '@/shared/utils/cn';

// Mirrors wemarketplus-site `.field label`: 12px, weight 700, #8b9fc4,
// uppercase, letter-spacing .04em, 6px bottom margin.
export const Label = forwardRef<HTMLLabelElement, LabelHTMLAttributes<HTMLLabelElement>>(
  ({ className, ...props }, ref) => (
    <label
      ref={ref}
      className={cn(
        'mb-1.5 block text-[12px] font-bold uppercase tracking-label text-muted-soft',
        className,
      )}
      {...props}
    />
  ),
);
Label.displayName = 'Label';
