import { Card, CardContent } from '@/shared/ui/core';
import type { Apartment } from '@/shared/types';
import { occupancyRate } from '../utils/occupancy';

export function OccupancyHero({ apartments }: { apartments: readonly Apartment[] }) {
  const rate = occupancyRate(apartments);
  return (
    <Card>
      <CardContent className="space-y-1 px-6 py-5">
        <p className="text-[10px] uppercase tracking-label text-muted-soft">
          Occupancy
        </p>
        <p className="font-display text-4xl leading-none text-foreground">
          {(rate * 100).toFixed(0)}%
        </p>
        <p className="text-xs text-muted">
          {apartments.length} units total
        </p>
      </CardContent>
    </Card>
  );
}
