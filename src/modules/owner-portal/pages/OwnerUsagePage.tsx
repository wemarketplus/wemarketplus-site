import { DataTable, type Column } from '@/shared/ui/data-display';
import { formatRelative } from '@/shared/utils/dateFormatter';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OWNER_USAGE } from '../constants/ownerFixtures';
import type { OwnerUsageRow } from '../types/ownerPortalTypes';

const columns: ReadonlyArray<Column<OwnerUsageRow>> = [
  {
    key: 'org',
    header: 'Organization',
    cell: (u) => <span className="font-bold text-[#111]">{u.organization}</span>,
  },
  {
    key: 'seats',
    header: 'Seats',
    cell: (u) => (
      <>
        <span className="text-[#111]">
          {u.seatsUsed} / {u.seatsBilled}
        </span>
        <span className="ml-2 text-[10px] uppercase tracking-[0.08em] text-[#667]">
          {((u.seatsUsed / u.seatsBilled) * 100).toFixed(0)}%
        </span>
      </>
    ),
  },
  { key: 'api', header: 'API (30d)', cell: (u) => u.apiCallsLast30d.toLocaleString() },
  { key: 'active', header: 'Last active', cell: (u) => formatRelative(u.lastActiveAt) },
];

export function OwnerUsagePage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Product usage"
        description="Seat consumption and API activity per customer."
      />
      <DataTable columns={columns} rows={OWNER_USAGE} rowKey={(u) => u.id} />
    </div>
  );
}
