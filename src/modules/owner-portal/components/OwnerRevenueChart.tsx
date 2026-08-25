import { Card, CardContent } from '@/shared/ui/core';
import { formatCompactMoney } from '../utils/ownerFormat';
import { getMaxMrr } from '../utils/ownerRevenue';
import type { OwnerRevenueChartProps } from '../types/ownerPortalTypes';

export function OwnerRevenueChart({ months }: OwnerRevenueChartProps) {
  const maxMrr = getMaxMrr(months);

  return (
    <Card dense>
      <CardContent className="px-6 py-6">
        <div className="grid grid-cols-5 items-end gap-4 sm:gap-6">
          {months.map((m) => {
            const heightPct = (m.mrr / maxMrr) * 100;
            return (
              <div key={m.month} className="flex flex-col items-center gap-2">
                <div className="flex h-44 w-full items-end overflow-hidden rounded-md bg-foreground/[0.04]">
                  <div
                    className="w-full rounded-md bg-gradient-to-t from-primary to-azure transition-all"
                    style={{ height: `${heightPct}%` }}
                  />
                </div>
                <p className="text-xs font-semibold text-foreground">{m.month}</p>
                <p className="text-[10px] uppercase tracking-label text-muted-soft">
                  {formatCompactMoney(m.mrr)}
                </p>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
