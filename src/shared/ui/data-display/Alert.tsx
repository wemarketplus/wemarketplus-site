import type { HTMLAttributes } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/shared/utils/cn';

// `.alert` family: soft tinted fill, hairline border, accent-coloured text.
// Driven by tokens rather than literal hex so the tones track the palette —
// the previous values (#79c0ff on a .07 fill) were tuned for a navy page and
// were unreadable once the app moved to the light editorial theme.
const alertVariants = cva('rounded-md px-3.5 py-2.5 text-[13px]', {
  variants: {
    tone: {
      b: 'border border-azure/25 bg-azure/[0.06] text-azure',
      y: 'border border-warning/25 bg-warning/[0.08] text-warning',
      g: 'border border-success/25 bg-success/[0.07] text-success',
      r: 'border border-destructive/25 bg-destructive/[0.07] text-destructive',
      gd: 'border border-gold/25 bg-gold/[0.08] text-gold',
    },
  },
  defaultVariants: { tone: 'b' },
});

export interface AlertProps
  extends HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof alertVariants> {}

export function Alert({ className, tone, ...props }: AlertProps) {
  return <div className={cn(alertVariants({ tone }), className)} {...props} />;
}
