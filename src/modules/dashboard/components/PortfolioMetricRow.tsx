import type { ReactNode } from 'react';
import { cn } from '@/shared/utils/cn';

/**
 * One label/value line inside a Portfolio Dashboard card — the shape the client's
 * reference design uses for Financial Overview ("Rent Roll … $13,000/mo").
 *
 * The value carries the emphasis and an optional tone, because the owner reads down
 * the right-hand column: these cards exist so a figure that needs attention is
 * findable without reading the labels.
 */
const TONE_TEXT = {
  neutral: 'text-foreground',
  positive: 'text-[#136c32]',
  caution: 'text-[#7a5a00]',
  negative: 'text-[#8f1f1f]',
  info: 'text-[#0f5c8a]',
} as const;

export type PortfolioRowTone = keyof typeof TONE_TEXT;

export function PortfolioMetricRow({
  label,
  value,
  detail,
  tone = 'neutral',
  last = false,
}: {
  label: ReactNode;
  value: ReactNode;
  /** Optional second line under the label, for the "3 referrals" style hint. */
  detail?: ReactNode;
  tone?: PortfolioRowTone;
  /** Drops the divider on the final row so the card does not end in a rule. */
  last?: boolean;
}) {
  return (
    <div
      className={cn(
        'flex items-baseline justify-between gap-3 py-2.5',
        !last && 'border-b border-border/[0.07]',
      )}
    >
      <div className="min-w-0">
        <span className="text-[12px] text-muted">{label}</span>
        {detail && (
          <span className="block text-[11px] text-muted/80">{detail}</span>
        )}
      </div>
      <span
        className={cn(
          'shrink-0 text-[15px] font-extrabold leading-none',
          TONE_TEXT[tone],
        )}
      >
        {value}
      </span>
    </div>
  );
}
