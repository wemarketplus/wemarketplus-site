import { HandCoins } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatUsd } from '@/modules/cl-financial/utils/financialFormat';
import {
  FEE_STATUS_LABELS,
  FEE_STATUS_OPTIONS,
  FEE_STATUS_PILL,
  URGENCY_LABELS,
  URGENCY_PILL,
} from '../constants/paidReferralsConstants';
import { num } from '../utils/paidReferralsUtils';
import type { ClPaidReferralRecord } from '../types/clReferralsApiTypes';

const CARE_LABELS: Record<string, string> = { IL: 'Independent', AL: 'Assisted', MC: 'Memory care' };

interface PaidReferralsTableProps {
  referrals: readonly ClPaidReferralRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (r: ClPaidReferralRecord) => void;
  onDelete: (r: ClPaidReferralRecord) => void;
  onFeeStatusChange: (r: ClPaidReferralRecord, status: string) => void;
  onAdd?: () => void;
}

export function PaidReferralsTable({
  referrals,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onFeeStatusChange,
  onAdd,
}: PaidReferralsTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClPaidReferralRecord>> = [
    {
      key: 'prospect',
      header: 'Prospect',
      cell: (r) => (
        <div>
          <p className="font-bold text-foreground">{r.prospectName}</p>
          <p className="text-[11px] text-muted">{r.stage ?? 'New Referral'}</p>
        </div>
      ),
    },
    {
      key: 'care',
      header: 'Care',
      cell: (r) => (r.careLevel ? (CARE_LABELS[r.careLevel] ?? r.careLevel) : '—'),
    },
    { key: 'source', header: 'Source', cell: (r) => r.sourceName },
    {
      key: 'fee',
      header: 'Fee',
      cell: (r) => (r.referralFee != null ? formatUsd(num(r.referralFee)) : '—'),
    },
    {
      key: 'feeStatus',
      header: 'Fee status',
      cell: (r) => (
        <span className="inline-flex items-center gap-2">
          <Pill tone={FEE_STATUS_PILL[r.feeStatus]}>{FEE_STATUS_LABELS[r.feeStatus]}</Pill>
          <select
            aria-label={`Change fee status for ${r.prospectName}`}
            value={r.feeStatus}
            disabled={isMutating}
            onChange={(e) => onFeeStatusChange(r, e.target.value)}
            className="rounded-md border border-border/[0.15] bg-white px-1.5 py-1 text-[11px] text-foreground"
          >
            {FEE_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </span>
      ),
    },
    {
      key: 'urgency',
      header: 'Urgency',
      cell: (r) => <Pill tone={URGENCY_PILL[r.urgency]}>{URGENCY_LABELS[r.urgency]}</Pill>,
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (r) => (
        <EntityRowActions
          onEdit={() => onEdit(r)}
          onDelete={canDelete ? () => onDelete(r) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${r.prospectName}`}
          deleteLabel={`Delete ${r.prospectName}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={referrals}
      rowKey={(r) => r.id}
      empty={
        hasFilters ? (
          'No paid referrals match the current filters.'
        ) : (
          <EmptyState
            icon={HandCoins}
            title="No paid referrals yet"
            description="Log placement-agency referrals to track fees owed and conversion."
            actionLabel={onAdd ? 'Add referral' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
