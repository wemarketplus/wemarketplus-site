import { Link } from 'react-router-dom';
import { Card } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import type { DashboardStatCard } from '../types/dashboardTypes';
import { statToneDotClass } from '../utils/dashboardUtils';

// Tinted icon chip in the tile's top-right corner. The tone shows only here —
// the numeral stays ink-dark — which is what keeps a row of four tiles calm.
const TONE_CHIP: Record<NonNullable<DashboardStatCard['tone']>, string> = {
  primary: 'bg-primary/[0.08] text-primary',
  azure: 'bg-azure/[0.10] text-azure',
  amber: 'bg-amber/[0.10] text-amber',
  success: 'bg-success/[0.10] text-success',
  warning: 'bg-warning/[0.12] text-warning',
  destructive: 'bg-destructive/[0.10] text-destructive',
};

export function DashboardStatTile({ stat }: { stat: DashboardStatCard }) {
  const Icon = stat.icon;

  const body = (
    <Card
      dense
      className={cn(
        'h-full px-5 py-5',
        // Only a tile that goes somewhere gets affordances. A hover state on a
        // tile that does nothing is a promise the tile cannot keep.
        stat.to &&
          'transition-colors hover:border-primary/25 hover:bg-primary/[0.02]',
      )}
    >
      <div className="flex items-start justify-between gap-3">
        <p className="max-w-[8.5rem] text-[10.5px] font-semibold uppercase leading-[1.35] tracking-label text-muted-soft">
          {stat.label}
        </p>
        {Icon && (
          <div
            className={cn(
              'flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-md',
              TONE_CHIP[stat.tone ?? 'primary'],
            )}
          >
            <Icon className="h-4 w-4" />
          </div>
        )}
      </div>

      <p className="mt-5 text-[40px] font-bold leading-none tracking-[-0.02em] text-foreground">
        {stat.value}
      </p>

      {stat.hint && (
        <p className="mt-4 inline-flex items-center gap-1.5 text-[12.5px] text-muted">
          <span
            className={cn(
              'h-1.5 w-1.5 shrink-0 rounded-full',
              statToneDotClass(stat.tone),
            )}
          />
          {stat.hint}
        </p>
      )}
    </Card>
  );

  // The whole tile is the target, not a "view" link tucked in a corner: the
  // number IS the thing being clicked, and a 40px numeral is a far easier hit
  // than a caption. `aria-label` names the destination, because "12" on its own
  // tells a screen-reader user nothing about where the link goes.
  return stat.to ? (
    <Link
      to={stat.to}
      aria-label={`${stat.label}: ${stat.value}`}
      className="block rounded-card focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/40"
    >
      {body}
    </Link>
  ) : (
    body
  );
}
