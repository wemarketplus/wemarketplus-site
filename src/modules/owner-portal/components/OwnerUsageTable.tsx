import { DataTable, type Column } from '@/shared/ui/data-display';
import { formatRelative } from '@/shared/utils/dateFormatter';
import type { OwnerUsageRow, OwnerUsageTableProps } from '../types/ownerPortalTypes';

const columns: ReadonlyArray<Column<OwnerUsageRow>> = [
  {
    key: 'org',
    header: 'Organization',
    cell: (u) => <span className="font-bold text-foreground">{u.organization}</span>,
  },
  {
    key: 'seats',
    header: 'Seats',
    cell: (u) => (
      <>
        <span className="text-foreground">
          {u.seatsUsed} / {u.seatsBilled}
        </span>
        <span className="ml-2 text-[10px] uppercase tracking-label text-muted">
          {((u.seatsUsed / u.seatsBilled) * 100).toFixed(0)}%
        </span>
      </>
    ),
  },
  { key: 'api', header: 'API (30d)', cell: (u) => u.apiCallsLast30d.toLocaleString() },
  { key: 'active', header: 'Last active', cell: (u) => formatRelative(u.lastActiveAt) },
];

export function OwnerUsageTable({ rows }: OwnerUsageTableProps) {
  return <DataTable columns={columns} rows={rows} rowKey={(u) => u.id} />;
}
