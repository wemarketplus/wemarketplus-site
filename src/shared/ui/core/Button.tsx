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
        // reset-password.html gradient azure→lime
        gradient:
          'rounded-pill text-[#081426] hover:opacity-[0.88] bg-[linear-gradient(90deg,#49b6ff,#8cff66)]',
        // subtle filled secondary used across the site
        secondary:
          'rounded-pill border border-white/[0.12] bg-surface-raised text-foreground hover:border-white/25',
        outline:
          'rounded-pill border border-white/[0.14] bg-transparent text-foreground hover:bg-white/[0.05]',
        ghost:
          'rounded-pill bg-transparent text-muted hover:text-foreground hover:bg-white/[0.05]',
        destructive:
          'rounded-pill bg-destructive text-[#081426] hover:opacity-[0.88]',
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
