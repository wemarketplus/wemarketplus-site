import { Card, CardContent } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import type { Territory } from '@/shared/types';
import { maxAdmissions } from '../utils/schedulingUtils';

// Lightweight visual — each territory rendered as a tile with intensity
// proportional to its admissions count. Replace with a real map when
// Mapbox/Leaflet is wired.
export function TerritoryHeatmap({ territories }: { territories: readonly Territory[] }) {
  const max = maxAdmissions(territories);
  return (
    <Card>
      <CardContent className="px-6 py-6">
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {territories.map((t) => {
            const intensity = Math.min(1, t.admissionsCount / max);
            return (
              <div
                key={t.id}
                className={cn(
                  'flex h-32 flex-col justify-between rounded-md border border-border/[0.08] p-3 transition-colors',
                )}
                style={{
                  background: `rgba(var(--color-primary) / ${0.08 + intensity * 0.25})`,
                }}
              >
                <p className="text-xs font-semibold text-foreground">{t.areaName}</p>
                <div>
                  <p className="font-display text-2xl leading-none text-foreground">
                    {t.admissionsCount}
                  </p>
                  <p className="mt-0.5 text-[10px] uppercase tracking-label text-muted-soft">
                    {t.assignedMarketer}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}
