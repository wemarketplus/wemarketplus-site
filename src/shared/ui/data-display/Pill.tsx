import type { HTMLAttributes } from 'react';
import { cva, type VariantProps } from 'class-variance-authority';
import { cn } from '@/shared/utils/cn';

/**
 * The badge geometry — ONE height, padding, radius, size and weight for every
 * badge in the app, whatever it is saying.
 *
 * Split out from the colours below because badges were drifting on shape, not
 * on hue: the status pills were `inline-block` with vertical padding, so their
 * height came from their own line box, while the urgency chips next to them set
 * `py-0.5` at a smaller font — two badges in the same row, a couple of pixels
 * apart, with subtly different corner radii. `inline-flex` at a FIXED height
 * makes every badge the same object regardless of what is inside it, including
 * ones whose text has no descenders.
 *
 * Exported so the interactive StatusSelect can wear exactly this shape without
 * restating it.
 */
export const PILL_SHAPE =
  'inline-flex h-[22px] shrink-0 items-center rounded-pill px-2.5 text-[11px] font-extrabold leading-none whitespace-nowrap';

// Mirrors wemarketplus-site `.pill` family — pastel fills with dark text.
// tone names match the source suffixes (g/b/r/y/p/gd).
export const PILL_TONES = {
  g: 'bg-[#d8ffe2] text-[#136c32]',
  b: 'bg-[#dff1ff] text-[#0f5c8a]',
  r: 'bg-[#ffd9d9] text-[#8f1f1f]',
  y: 'bg-[#fff3cf] text-[#7a5a00]',
  p: 'bg-[#efe5ff] text-[#5b3aa0]',
  gd: 'bg-[#fff3cd] text-[#92570b]',
  /**
   * No colours of its own — the caller supplies them via `className`. For the
   * badges whose palette is token-driven rather than one of the six pastels
   * (the Hot/Warm/Cold urgency chips, which use destructive/warning/azure at a
   * tint). They get the shared SHAPE without a duplicate set of geometry
   * classes, which is what made them the odd ones out.
   */
  none: '',
} as const;

const pillVariants = cva(PILL_SHAPE, {
  variants: { tone: PILL_TONES },
  defaultVariants: { tone: 'b' },
});

export interface PillProps
  extends HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof pillVariants> {}

export function Pill({ className, tone, ...props }: PillProps) {
  return <span className={cn(pillVariants({ tone }), className)} {...props} />;
}
