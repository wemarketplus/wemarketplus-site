import { Card, CardContent } from '@/shared/ui/core';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { MileageEntry } from '@/shared/types';
import { totalMiles } from '../utils/totalMileage';
import type { MileageListProps } from '../types/clOutreachTypes';

const columns: ReadonlyArray<Column<MileageEntry>> = [
  { key: 'date', header: 'Date', cell: (e) => formatDate(e.date) },
  {
    key: 'distance',
    header: 'Distance',
    cell: (e) => <span className="font-bold text-foreground">{e.distanceMiles.toFixed(1)} mi</span>,
  },
  { key: 'purpose', header: 'Purpose', cell: (e) => e.purpose },
];

export function MileageList({ entries }: MileageListProps) {
  return (
    <div className="space-y-4">
      <Card dense>
        <CardContent className="space-y-1 px-6 py-5">
          <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
            Total this period
          </p>
          <p className="text-[26px] font-black leading-none text-foreground">
            {totalMiles(entries).toFixed(1)} mi
          </p>
        </CardContent>
      </Card>
      <DataTable columns={columns} rows={entries} rowKey={(e) => e.id} />
    </div>
  );
}
