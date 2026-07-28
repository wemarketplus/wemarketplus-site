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

  return (
    <Card dense className="px-5 py-5">
      <div className="flex items-start justify-between gap-3">
        <p className="max-w-[8.5rem] text-[10.5px] font-semibold uppercase leading-[1.35] tracking-[0.12em] text-muted-soft">
          {stat.label}
        </p>
        {Icon && (
          <div
            className={cn(
              'flex h-[30px] w-[30px] shrink-0 items-center justify-center rounded-[9px]',
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
}
