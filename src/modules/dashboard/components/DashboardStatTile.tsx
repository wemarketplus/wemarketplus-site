import { Card, CardContent } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import type { DashboardStatCard } from '../types/dashboardTypes';
import { statToneDotClass } from '../utils/dashboardUtils';

export function DashboardStatTile({ stat }: { stat: DashboardStatCard }) {
  return (
    <Card className="overflow-hidden">
      <CardContent className="space-y-3 px-5 py-5">
        <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
          {stat.label}
        </p>
        <p className="font-display text-4xl leading-none text-foreground">
          {stat.value}
        </p>
        {stat.hint && (
          <p className="inline-flex items-center gap-1.5 rounded-pill bg-white/[0.04] px-2 py-0.5 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
            <span
              className={cn(
                'h-1 w-1 animate-breathe rounded-full',
                statToneDotClass(stat.tone),
              )}
            />
            {stat.hint}
          </p>
        )}
      </CardContent>
    </Card>
  );
}
