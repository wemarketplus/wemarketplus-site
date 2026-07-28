import { Landmark } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { formatUsd } from '../utils/financialFormat';
import { num } from '../utils/clFinancialMappers';
import type { ClRevenueEntryRecord } from '../types/clFinancialApiTypes';

interface RevenueTableProps {
  entries: readonly ClRevenueEntryRecord[];
  leakage?: boolean;
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (r: ClRevenueEntryRecord) => void;
  onDelete: (r: ClRevenueEntryRecord) => void;
  onAdd?: () => void;
}

// Ledger and Leakage share this table: Leakage adds Budget + Variance columns to
// surface where actual revenue fell short of budget.
export function RevenueTable({
  entries,
  leakage,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onAdd,
}: RevenueTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: Array<Column<ClRevenueEntryRecord>> = [
    { key: 'date', header: 'Date', cell: (r) => formatDate(r.entryDate) },
    { key: 'category', header: 'Category', cell: (r) => r.category ?? '—' },
    {
      key: 'amount',
      header: 'Amount',
      cell: (r) => <span className="font-bold text-[#111]">{formatUsd(num(r.amount))}</span>,
    },
  ];

  if (leakage) {
    columns.push(
      {
        key: 'budget',
        header: 'Budget',
        cell: (r) => (r.budgetAmount != null ? formatUsd(num(r.budgetAmount)) : '—'),
      },
      {
        key: 'variance',
        header: 'Variance',
        cell: (r) => {
          if (r.budgetAmount == null) return '—';
          const variance = num(r.amount) - num(r.budgetAmount);
          const short = variance < 0;
          return (
            <span className={short ? 'font-semibold text-destructive' : 'text-success'}>
              {short ? '-' : '+'}
              {formatUsd(Math.abs(variance))}
            </span>
          );
        },
      },
    );
  } else {
    columns.push({ key: 'desc', header: 'Description', cell: (r) => r.description ?? '—' });
  }

  columns.push({
    key: 'actions',
    header: '',
    headerClassName: 'w-20',
    className: 'text-right',
    cell: (r) => (
      <EntityRowActions
        onEdit={() => onEdit(r)}
        onDelete={canDelete ? () => onDelete(r) : undefined}
        disabled={isMutating}
        editLabel="Edit entry"
        deleteLabel="Delete entry"
      />
    ),
  });

  return (
    <DataTable
      columns={columns}
      rows={entries}
      rowKey={(r) => r.id}
      empty={
        hasFilters ? (
          'No entries match the current filters.'
        ) : (
          <EmptyState
            icon={Landmark}
            title="No ledger entries yet"
            description="Record revenue against budget to track the rent roll and surface leakage."
            actionLabel={onAdd ? 'Add entry' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
