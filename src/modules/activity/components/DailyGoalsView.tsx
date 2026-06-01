import { Card, CardContent } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { useDailyGoals } from '../hooks/useDailyGoals';

export function DailyGoalsView() {
  const { goals } = useDailyGoals();

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
      {goals.map((g) => {
        const pct = Math.min(100, Math.round((g.current / g.target) * 100));
        const hit = g.current >= g.target;
        return (
          <Card key={g.id}>
            <CardContent className="space-y-3 px-5 py-5">
              <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
                {g.label}
              </p>
              <p className="font-display text-3xl leading-none text-foreground">
                {g.current}
                <span className="text-base text-muted-soft"> / {g.target}</span>
              </p>
              <div className="h-1.5 w-full overflow-hidden rounded-pill bg-white/[0.06]">
                <div
                  className={cn(
                    'h-full rounded-pill transition-all',
                    hit ? 'bg-success' : 'bg-primary',
                  )}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
