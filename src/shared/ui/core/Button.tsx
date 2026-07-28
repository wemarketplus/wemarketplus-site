import { forwardRef, type ButtonHTMLAttributes } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/shared/utils/cn';

// Mirrors wemarketplus-site `.btn-login` / `.btn-main`: pill-shaped, primary
// accent fill with dark text, weight 800, hover via opacity .88. The accent
// is `--color-primary` so a [data-product] scope recolors it (azure ↔ amber).
const buttonVariants = cva(
  'inline-flex items-center justify-center gap-2 font-extrabold transition-opacity duration-150 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/50 disabled:cursor-not-allowed disabled:opacity-50',
  {
    variants: {
      variant: {
        // .btn-login / .btn-main — solid accent pill, dark text
        primary:
          'rounded-pill bg-primary text-primary-foreground hover:opacity-[0.88]',
        // reset-password.html gradient. Retuned for the light theme: the old
        // #49b6ff→#8cff66 ramp was a dark-canvas accent and washed out on white.
        gradient:
          'rounded-pill text-primary-foreground hover:opacity-[0.88] bg-[linear-gradient(90deg,#0f5c44,#16805c)]',
        // subtle filled secondary used across the site
        secondary:
          'rounded-pill border border-border/[0.12] bg-surface-raised text-foreground hover:border-border/25',
        outline:
          'rounded-pill border border-border/[0.14] bg-transparent text-foreground hover:bg-foreground/[0.05]',
        ghost:
          'rounded-pill bg-transparent text-muted hover:text-foreground hover:bg-foreground/[0.05]',
        destructive:
          'rounded-pill bg-destructive text-destructive-foreground hover:opacity-[0.88]',
        link: 'bg-transparent text-primary hover:underline underline-offset-4',
      },
      size: {
        sm: 'h-9 px-4 text-[13px]',
        md: 'h-11 px-5 text-[14px]',
        lg: 'h-12 px-6 text-[15px]',
        block: 'w-full py-[13px] text-[15px]',
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
