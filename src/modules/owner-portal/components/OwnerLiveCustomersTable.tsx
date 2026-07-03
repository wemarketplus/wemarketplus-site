import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { Button } from '@/shared/ui/core';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { PillProps } from '@/shared/ui/data-display';
import type { OwnerCustomer } from '../types/ownerPortalApiTypes';

// Live customer database — backed by GET /owner/customers (TenantResponseDto).
// Distinct from the fixture OwnerCustomersTable (mrr/healthScore), which the
// backend does not yet expose.
interface OwnerLiveCustomersTableProps {
  customers: readonly OwnerCustomer[];
  onSuspend: (customer: OwnerCustomer) => void;
  suspendingId: string | null;
  onImpersonate: (customer: OwnerCustomer) => void;
  impersonatingId: string | null;
}

const SUB_TONE: Record<string, PillProps['tone']> = {
  active: 'g',
  trialing: 'b',
  past_due: 'y',
  canceled: 'r',
  incomplete: 'y',
  unpaid: 'r',
};

function subTone(status: string): PillProps['tone'] {
  return SUB_TONE[status] ?? 'p';
}

export function OwnerLiveCustomersTable({
  customers,
  onSuspend,
  suspendingId,
  onImpersonate,
  impersonatingId,
}: OwnerLiveCustomersTableProps) {
  const columns: ReadonlyArray<Column<OwnerCustomer>> = [
    {
      key: 'name',
      header: 'Organization',
      cell: (c) => <span className="font-bold text-[#111]">{c.name}</span>,
    },
    {
      key: 'location',
      header: 'Location',
      cell: (c) => [c.city, c.state].filter(Boolean).join(', ') || '—',
    },
    { key: 'product', header: 'Product', cell: (c) => c.product },
    { key: 'crmTier', header: 'Tier', cell: (c) => c.crmTier },
    {
      key: 'subscriptionStatus',
      header: 'Subscription',
      cell: (c) => (
        <Pill tone={subTone(c.subscriptionStatus)}>
          {c.subscriptionStatus.replace('_', ' ')}
        </Pill>
      ),
    },
    {
      key: 'isActive',
      header: 'State',
      cell: (c) => (
        <Pill tone={c.isActive ? 'g' : 'r'}>{c.isActive ? 'active' : 'suspended'}</Pill>
      ),
    },
    { key: 'joined', header: 'Joined', cell: (c) => formatDate(c.createdAt) },
    {
      key: 'actions',
      header: '',
      cell: (c) => (
        <div className="flex justify-end gap-2">
          <Button
            variant="secondary"
            size="sm"
            disabled={!c.isActive || impersonatingId === c.id}
            onClick={() => onImpersonate(c)}
          >
            {impersonatingId === c.id ? 'Entering…' : 'Impersonate'}
          </Button>
          <Button
            variant="destructive"
            size="sm"
            disabled={!c.isActive || suspendingId === c.id}
            onClick={() => onSuspend(c)}
          >
            {suspendingId === c.id ? 'Suspending…' : 'Suspend'}
          </Button>
        </div>
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={customers}
      rowKey={(c) => c.id}
      empty="No customer accounts yet."
    />
  );
}
