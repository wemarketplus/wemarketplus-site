import type { HTMLAttributes } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/shared/utils/cn';

// Mirrors wemarketplus-site `.pill` family exactly — pastel fills with dark
// text. tone names match the source suffixes (g/b/r/y/p/gd).
const pillVariants = cva(
  'inline-block rounded-pill px-2.5 py-[3px] text-[11px] font-extrabold leading-tight',
  {
    variants: {
      tone: {
        g: 'bg-[#d8ffe2] text-[#136c32]',
        b: 'bg-[#dff1ff] text-[#0f5c8a]',
        r: 'bg-[#ffd9d9] text-[#8f1f1f]',
        y: 'bg-[#fff3cf] text-[#7a5a00]',
        p: 'bg-[#efe5ff] text-[#5b3aa0]',
        gd: 'bg-[#fff3cd] text-[#92570b]',
      },
    },
    defaultVariants: { tone: 'b' },
  },
);

export interface PillProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof pillVariants> {}

export function Pill({ className, tone, ...props }: PillProps) {
  return <span className={cn(pillVariants({ tone }), className)} {...props} />;
}
