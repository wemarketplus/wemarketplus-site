import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { formatMoney, formatPercent } from '../utils/ownerFormat';
import { healthToneClass } from '../utils/ownerHealthClass';
import { STATUS_PILL } from '../constants/ownerScreenConstants';
import type { OwnerCustomer, OwnerCustomersTableProps } from '../types/ownerPortalTypes';

const columns: ReadonlyArray<Column<OwnerCustomer>> = [
  {
    key: 'organization',
    header: 'Organization',
    cell: (c) => <span className="font-bold text-[#111]">{c.organization}</span>,
  },
  { key: 'plan', header: 'Plan', cell: (c) => c.plan },
  { key: 'mrr', header: 'MRR', cell: (c) => formatMoney(c.mrr) },
  {
    key: 'status',
    header: 'Status',
    cell: (c) => <Pill tone={STATUS_PILL[c.status]}>{c.status.replace('_', ' ')}</Pill>,
  },
  {
    key: 'health',
    header: 'Health',
    cell: (c) => (
      <span className={`font-semibold ${healthToneClass(c.healthScore)}`}>
        {formatPercent(c.healthScore, 0)}
      </span>
    ),
  },
  { key: 'joined', header: 'Joined', cell: (c) => formatDate(c.joinedAt) },
];

export function OwnerCustomersTable({ customers }: OwnerCustomersTableProps) {
  return <DataTable columns={columns} rows={customers} rowKey={(c) => c.id} />;
}
