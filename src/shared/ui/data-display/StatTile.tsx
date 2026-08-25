import type { ComponentType } from 'react';
import { cn } from '@/shared/utils/cn';

export type StatTone = 'b' | 'g' | 'gd' | 'r' | 'y';

interface StatTileProps {
  label: string;
  value: string;
  hint?: string;
  tone?: StatTone;
  icon?: ComponentType<{ className?: string }>;
}

// "Editorial calm" stat card: a white hairline card, not a tinted fill. The
// numeral stays ink-dark and the tone shows only in the small icon chip —
// that restraint is what keeps the accents quiet across a row of four.
const TONE_CHIP: Record<StatTone, string> = {
  b: 'bg-primary/[0.08] text-primary',
  g: 'bg-success/[0.10] text-success',
  gd: 'bg-gold/[0.12] text-gold',
  r: 'bg-destructive/[0.10] text-destructive',
  y: 'bg-warning/[0.12] text-warning',
};

export function StatTile({ label, value, hint, tone = 'b', icon: Icon }: StatTileProps) {
  return (
    <div className="rounded-card border border-border/[0.09] bg-surface px-5 py-5">
      <div className="flex items-start justify-between gap-3">
        <p className="max-w-[8.5rem] text-[10.5px] font-semibold uppercase leading-[1.35] tracking-label text-muted-soft">
          {label}
        </p>
        {Icon && (
          <div
            className={cn(
              'flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-md',
              TONE_CHIP[tone],
            )}
          >
            <Icon className="h-4 w-4" />
          </div>
        )}
      </div>

      <p className="mt-5 text-[40px] font-bold leading-none tracking-[-0.02em] text-foreground">
        {value}
      </p>

      {hint && <p className="mt-4 text-[12.5px] text-muted">{hint}</p>}
    </div>
  );
}
