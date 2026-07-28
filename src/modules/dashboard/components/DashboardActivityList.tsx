import { Card, CardContent } from '@/shared/ui/core';
import { formatDateTime, formatRelative } from '@/shared/utils/dateFormatter';
import type { DashboardActivityItem } from '../types/dashboardTypes';

interface DashboardActivityListProps {
  items: readonly DashboardActivityItem[];
}

/**
 * Audit-backed activity feed. Every row shows WHAT happened, WHO did it and WHEN
 * — the absolute date/time (so it is auditable) plus a relative age (so it is
 * scannable). Rows come from the tamper-evident audit log, not a separate table.
 */
export function DashboardActivityList({ items }: DashboardActivityListProps) {
  return (
    <Card>
      <CardContent className="px-0 pt-0 pb-0">
        <header className="px-6 py-4">
          <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
            Recent activity
          </p>
        </header>
        {items.length === 0 && (
          <p className="px-6 pb-4 text-xs text-muted">No recent activity yet.</p>
        )}
        <ul className="divide-y divide-border">
          {items.map((a) => (
            <li key={a.id} className="flex items-start gap-3 px-6 py-3">
              <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-primary" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-foreground">{a.title}</p>
                <p className="mt-0.5 truncate text-xs text-muted">
                  {a.actorName}
                  {a.actorEmail && (
                    <span className="text-muted-soft"> · {a.actorEmail}</span>
                  )}
                </p>
              </div>
              <div className="shrink-0 text-right">
                <p className="text-[11px] text-foreground">
                  {formatDateTime(a.occurredAt)}
                </p>
                <p className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                  {formatRelative(a.occurredAt)}
                </p>
              </div>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
