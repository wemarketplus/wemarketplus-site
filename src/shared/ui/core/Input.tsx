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
        className,
      )}
      {...props}
    />
  ),
);
Input.displayName = 'Input';
