import { Card, CardContent } from '@/shared/ui/core';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  REMINDER_BUCKETS,
  REMINDER_BUCKET_LABELS,
  REMINDER_BUCKET_TONE,
} from '../constants/activityConstants';
import { useReminders } from '../hooks/useReminders';

export function RemindersView() {
  const { buckets } = useReminders();

  return (
    <div className="space-y-3">
      {REMINDER_BUCKETS.map((bucket) => {
        const items = buckets[bucket];
        if (items.length === 0) return null;
        return (
          <Card key={bucket}>
            <CardContent className="px-0 pt-0 pb-0">
              <header className="flex items-center justify-between px-6 py-3">
                <span
                  className={`rounded-pill border px-2.5 py-0.5 text-[10px] uppercase tracking-[0.08em] ${REMINDER_BUCKET_TONE[bucket]}`}
                >
                  {REMINDER_BUCKET_LABELS[bucket]}
                </span>
                <span className="text-[10px] text-muted-soft">{items.length}</span>
              </header>
              <ul className="divide-y divide-white/[0.06] border-t border-white/[0.06]">
                {items.map((r) => (
                  <li key={r.id} className="flex items-start justify-between gap-3 px-6 py-3">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold text-foreground">
                        {r.sourceName}
                      </p>
                      <p className="mt-0.5 text-xs text-muted">{r.actionDescription}</p>
                    </div>
                    <span className="shrink-0 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                      {formatDate(r.dueDate)}
                    </span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        );
      })}
    </div>
  );
}
