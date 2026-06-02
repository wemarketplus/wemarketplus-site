import type { ReactNode } from 'react';
import { cn } from '@/shared/utils/cn';

// Mirrors index.html .section-header / .section-kicker / .section-title /
// .section-body exactly: a tone-coloured pill kicker, an Instrument Serif
// weight-400 title at clamp(28px,4vw,48px), and a 500px-wide body, centred
// with a 52px gap below.
export type KickerTone = 'sage' | 'azure' | 'amber';

const KICKER_TONE: Record<KickerTone, string> = {
  sage: 'border-sage/[0.22] bg-sage/10 text-sage',
  azure: 'border-azure/[0.22] bg-azure/10 text-azure',
  amber: 'border-amber/[0.22] bg-amber/10 text-amber',
};

interface SectionHeadingProps {
  kicker: ReactNode;
  tone?: KickerTone;
  title: ReactNode;
  body?: ReactNode;
  className?: string;
}

export function SectionHeading({
  kicker,
  tone = 'sage',
  title,
  body,
  className,
}: SectionHeadingProps) {
  return (
    <div className={cn('mb-[52px] text-center', className)}>
      <div
        className={cn(
          'mb-[14px] inline-block rounded-pill border px-[13px] py-1 text-[11px] font-bold uppercase tracking-[0.09em]',
          KICKER_TONE[tone],
        )}
      >
        {kicker}
      </div>
      <h2 className="mb-3 font-serif-display text-[clamp(28px,4vw,48px)] font-normal leading-[1.08] tracking-[-0.02em] text-foreground">
        {title}
      </h2>
      {body ? (
        <p className="mx-auto max-w-[500px] text-[15px] leading-[1.75] text-muted">
          {body}
        </p>
      ) : null}
    </div>
  );
}
