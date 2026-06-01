import { Card, CardContent } from '@/shared/ui/core';
import { formatDate } from '@/shared/utils/dateFormatter';
import { PROSPECTS_FIXTURE } from '@/shared/fixtures';
import { cn } from '@/shared/utils/cn';

// Simple 7-day strip of upcoming follow-ups, derived from the prospects
// fixture. When `/calendar` ships, swap to a real API query.
export function CalendarView() {
  const events = [...PROSPECTS_FIXTURE].sort(
    (a, b) =>
      new Date(a.followUpDate).getTime() - new Date(b.followUpDate).getTime(),
  );

  return (
    <Card>
      <CardContent className="px-0 pt-0 pb-0">
        <header className="px-6 py-4">
          <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
            Upcoming follow-ups
          </p>
        </header>
        <ul className="divide-y divide-white/[0.06]">
          {events.map((e) => {
            const overdue = new Date(e.followUpDate).getTime() < Date.now();
            return (
              <li key={e.id} className="flex items-start gap-3 px-6 py-3">
                <span
                  className={cn(
                    'mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full',
                    overdue ? 'bg-destructive' : 'bg-primary',
                  )}
                />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold text-foreground">{e.name}</p>
                  <p className="mt-0.5 text-xs text-muted">{e.nextStep}</p>
                </div>
                <span className="shrink-0 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                  {formatDate(e.followUpDate)}
                </span>
              </li>
            );
          })}
        </ul>
      </CardContent>
    </Card>
  );
}
