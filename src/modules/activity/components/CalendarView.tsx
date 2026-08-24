import { Card, CardContent } from '@/shared/ui/core';
import { formatDate } from '@/shared/utils/dateFormatter';
import { cn } from '@/shared/utils/cn';
import { useCalendarEvents } from '../hooks/useCalendarEvents';
import { isEventOverdue } from '../utils/activityUtils';

export function CalendarView() {
  const { events, isEmpty } = useCalendarEvents();

  return (
    <Card>
      <CardContent className="px-0 pt-0 pb-0">
        <header className="px-6 py-4">
          <p className="text-[10px] uppercase tracking-label text-muted-soft">
            Upcoming follow-ups
          </p>
        </header>
        {isEmpty ? (
          <p className="px-6 py-6 text-xs text-muted-soft">
            No upcoming follow-ups.
          </p>
        ) : (
          <ul className="divide-y divide-white/[0.06]">
            {events.map((e) => {
            const overdue = isEventOverdue(e.followUpDate);
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
                <span className="shrink-0 text-[10px] uppercase tracking-label text-muted-soft">
                  {formatDate(e.followUpDate)}
                </span>
              </li>
            );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
