import { DataTable, Pill, type Column, type PillProps } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { OwnerScreenHeader } from '../components/OwnerScreenHeader';
import { OWNER_CUSTOMERS } from '../constants/ownerFixtures';
import type { OwnerCustomer } from '../types/ownerPortalTypes';
import { formatMoney, formatPercent } from '../utils/ownerFormat';
import { healthToneClass } from '../utils/ownerHealthClass';

const STATUS_PILL: Record<OwnerCustomer['status'], PillProps['tone']> = {
  active: 'g',
  past_due: 'y',
  churned: 'r',
};

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

export function OwnerCustomersPage() {
  return (
    <div className="space-y-6">
      <OwnerScreenHeader
        eyebrow="Owner portal"
        title="Customer database"
        description="Every active and churned account with health scores."
      />

      <DataTable columns={columns} rows={OWNER_CUSTOMERS} rowKey={(c) => c.id} />
    </div>
  );
}
