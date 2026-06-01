import { Card, CardContent } from '@/shared/ui/core';
import { formatDate } from '@/shared/utils/dateFormatter';
import { cn } from '@/shared/utils/cn';
import type { MakeReadyTicket } from '@/shared/types';

export function MakeReadyBoard({ tickets }: { tickets: readonly MakeReadyTicket[] }) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
      {tickets.map((t) => {
        const pct = Math.round(t.pctComplete * 100);
        const overdue =
          new Date(t.targetDate).getTime() < Date.now() && pct < 100;
        return (
          <Card key={t.id}>
            <CardContent className="space-y-3 px-5 py-5">
              <div className="flex items-center justify-between">
                <p className="font-display text-2xl text-foreground">
                  Unit {t.unitNumber}
                </p>
                <p
                  className={cn(
                    'text-[10px] font-semibold uppercase tracking-[0.08em]',
                    overdue ? 'text-destructive' : 'text-muted-soft',
                  )}
                >
                  {overdue ? 'Overdue' : 'On track'}
                </p>
              </div>
              <p className="text-xs text-muted">{t.unitType}</p>
              <div>
                <p className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                  {pct}% complete
                </p>
                <div className="mt-1 h-1.5 w-full overflow-hidden rounded-pill bg-white/[0.06]">
                  <div
                    className={cn(
                      'h-full rounded-pill transition-all',
                      pct >= 100 ? 'bg-success' : overdue ? 'bg-destructive' : 'bg-primary',
                    )}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
              <p className="text-[11px] text-muted">
                Target {formatDate(t.targetDate)} · {t.assignedTo}
              </p>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
