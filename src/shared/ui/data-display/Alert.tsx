import type { HTMLAttributes } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/shared/utils/cn';

// Mirrors wemarketplus-site `.alert` family: rgba .07 fill, .2 border, tinted
// text. tone names match the source suffixes (b/y/g/r/gd).
const alertVariants = cva('rounded-[9px] px-3.5 py-2.5 text-[13px]', {
  variants: {
    tone: {
      b: 'border border-[#49b6ff]/20 bg-[#49b6ff]/[0.07] text-[#79c0ff]',
      y: 'border border-[#fbbf24]/20 bg-[#fbbf24]/[0.07] text-[#fbbf24]',
      g: 'border border-[#8cff66]/20 bg-[#8cff66]/[0.07] text-[#8cff66]',
      r: 'border border-[#e05555]/20 bg-[#e05555]/[0.07] text-[#f87171]',
      gd: 'border border-[#ffd700]/20 bg-[#ffd700]/[0.07] text-[#ffd700]',
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
