import { Card, CardContent } from '@/shared/ui/core';
import { formatRelative } from '@/shared/utils/dateFormatter';
import type { DashboardActivityItem } from '../types/dashboardTypes';

interface DashboardActivityListProps {
  items: readonly DashboardActivityItem[];
}

export function DashboardActivityList({ items }: DashboardActivityListProps) {
  return (
    <Card>
      <CardContent className="px-0 pt-0 pb-0">
        <header className="px-6 py-4">
          <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
            Recent activity
          </p>
        </header>
        <ul className="divide-y divide-white/[0.06]">
          {items.map((a) => (
            <li key={a.id} className="flex items-start gap-3 px-6 py-3">
              <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-foreground">{a.title}</p>
                <p className="mt-0.5 text-xs text-muted">{a.detail}</p>
              </div>
              <span className="shrink-0 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                {formatRelative(a.occurredAt)}
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
