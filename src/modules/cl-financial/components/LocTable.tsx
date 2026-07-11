import { Calculator } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatUsd } from '../utils/financialFormat';
import { num } from '../utils/clFinancialMappers';
import type { ClLocPricingRecord } from '../types/clFinancialApiTypes';

interface LocTableProps {
  levels: readonly ClLocPricingRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (l: ClLocPricingRecord) => void;
  onDelete: (l: ClLocPricingRecord) => void;
  onAdd?: () => void;
}

export function LocTable({
  levels,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onAdd,
}: LocTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ClLocPricingRecord>> = [
    {
      key: 'level',
      header: 'Level',
      cell: (l) => <span className="font-bold text-[#111]">{l.level}</span>,
    },
    { key: 'label', header: 'Label', cell: (l) => l.label },
    {
      key: 'rate',
      header: 'Add-on rate',
      cell: (l) => (
        <span className="font-semibold text-[#111]">
          {l.addOnRate != null ? `${formatUsd(num(l.addOnRate))}/mo` : '—'}
        </span>
      ),
    },
    { key: 'desc', header: 'Description', cell: (l) => l.description ?? '—' },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (l) => (
        <EntityRowActions
          onEdit={() => onEdit(l)}
          onDelete={canDelete ? () => onDelete(l) : undefined}
          disabled={isMutating}
          editLabel="Edit level"
          deleteLabel="Delete level"
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={levels}
      rowKey={(l) => l.id}
      empty={
        hasFilters ? (
          'No levels match the current filters.'
        ) : (
          <EmptyState
            icon={Calculator}
            title="No care levels yet"
            description="Define level-of-care tiers and their monthly add-on rates to price admissions."
            actionLabel={onAdd ? 'Add level' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
