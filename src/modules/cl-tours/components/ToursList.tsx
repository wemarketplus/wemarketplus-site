import { Card, CardContent } from '@/shared/ui/core';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { Tour } from '@/shared/types';
import { TOUR_TYPE_LABEL } from '../constants/clToursConstants';

export function ToursList({ tours }: { tours: readonly Tour[] }) {
  return (
    <Card>
      <CardContent className="px-0 pt-0 pb-0">
        <ul className="divide-y divide-white/[0.06]">
          {tours.map((t) => (
            <li key={t.id} className="flex items-start gap-4 px-6 py-4">
              <div className="text-center">
                <p className="text-[10px] uppercase tracking-[0.12em] text-muted-soft">
                  {formatDate(t.tourDate)}
                </p>
                <p className="font-display text-xl leading-none text-foreground">
                  {t.tourTime}
                </p>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-foreground">
                  {t.prospectName}
                </p>
                <p className="mt-0.5 text-xs text-muted">
                  {TOUR_TYPE_LABEL[t.tourType]}
                  {t.notes ? ` · ${t.notes}` : ''}
                </p>
              </div>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}
