import { MapPin } from 'lucide-react';
import { Card, CardContent } from '@/shared/ui/core';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import type { CheckInListProps } from '../types/clOutreachTypes';

export function CheckInList({ items }: CheckInListProps) {
  return (
    <Card>
      <CardContent className="px-0 pt-0 pb-0">
        <ul className="divide-y divide-white/[0.06]">
          {items.map((c) => (
            <li key={c.id} className="flex items-start gap-3 px-6 py-4">
              <MapPin className="mt-0.5 h-4 w-4 text-primary" />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-foreground">
                  {c.organization}
                </p>
                <p className="text-xs text-muted">
                  {c.contactName} · {c.visitType}
                </p>
                <p className="mt-1 font-mono text-[10px] text-muted-soft">
                  {c.gpsLocation}
                </p>
              </div>
              <span className="shrink-0 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                {formatDateTime(c.visitDate)}
              </span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
