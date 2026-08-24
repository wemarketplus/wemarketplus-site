import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useMemo } from 'react';
import { Card, CardContent } from '@/shared/ui/core';
import { APARTMENT_STATUS_LABELS, APARTMENT_STATUS_PILL } from '../constants/clOperationsConstants';
import { Pill } from '@/shared/ui/data-display';
import { useListClApartmentsQuery } from '../api/clOperationsApi';
import { toApartment } from '../utils/clOperationsMappers';
import { OccupancyHero } from '../components/OccupancyHero';
import { ApartmentsTable } from '../components/ApartmentsTable';

// A management/Sales-Admissions read-only rollup: occupancy rate, a status
// breakdown, and the full unit list — the Gold/Max "Occupancy Overview" page
// shown alongside the dashboard in the demo. Read-only everywhere (edit a
// unit's status from Apartment Inventory instead).
export function OccupancyOverviewPage() {
  const { data, isLoading, error } = useListClApartmentsQuery({ page: 1, limit: 100 });
  const rows = useMemo(() => data?.data ?? [], [data]);
  const apartments = useMemo(() => rows.map(toApartment), [rows]);

  const byStatus = useMemo(() => {
    const counts = new Map<string, number>();
    for (const a of rows) counts.set(a.status, (counts.get(a.status) ?? 0) + 1);
    return Array.from(counts.entries());
  }, [rows]);

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>Occupancy overview</h1>
        <p className="text-sm text-muted">Portfolio-wide unit status at a glance.</p>
      </header>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <OccupancyHero apartments={apartments} />
        {byStatus.map(([status, count]) => (
          <Card key={status}>
            <CardContent className="space-y-1 px-6 py-5">
              <Pill tone={APARTMENT_STATUS_PILL[status as keyof typeof APARTMENT_STATUS_PILL]}>
                {APARTMENT_STATUS_LABELS[status as keyof typeof APARTMENT_STATUS_LABELS] ?? status}
              </Pill>
              <p className="font-display text-3xl leading-none text-foreground">{count}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Card>
        <CardContent className="pt-6">
          {error ? (
            <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
              Failed to load units.
            </p>
          ) : isLoading ? (
            <div className="rounded-card border border-border/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
              Loading…
            </div>
          ) : (
            <ApartmentsTable apartments={rows} isMutating={false} hasFilters={false} readOnly />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
