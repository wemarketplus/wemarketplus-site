import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { FUNDING_STATUS_LABELS } from '../constants/fundingConstants';
import type { FundingRecord } from '../types/fundingTypes';

interface FundingTableProps {
  rows: readonly FundingRecord[];
  isMutating: boolean;
  onEdit: (record: FundingRecord) => void;
  onDelete: (record: FundingRecord) => void;
}

export function FundingTable({ rows, isMutating, onEdit, onDelete }: FundingTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate on the action.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<FundingRecord>> = [
    {
      key: 'opportunity',
      header: 'Opportunity',
      cell: (f) => (
        <div>
          <p className="font-bold text-[#111]">{f.opportunityName}</p>
          {f.programType && <p className="text-[11px] text-[#667]">{f.programType}</p>}
        </div>
      ),
    },
    { key: 'status', header: 'Status', cell: (f) => FUNDING_STATUS_LABELS[f.status] ?? f.status },
    {
      key: 'maxAward',
      header: 'Max award / EIN',
      cell: (f) => (f.maxAwardPerEin != null ? `$${f.maxAwardPerEin.toLocaleString()}` : '—'),
    },
    {
      key: 'deadline',
      header: 'Deadline',
      cell: (f) => (f.applicationDeadline ? formatDate(f.applicationDeadline) : '—'),
    },
    { key: 'created', header: 'Added', cell: (f) => formatDate(f.createdAt) },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (f) => (
        <EntityRowActions
          onEdit={() => onEdit(f)}
          onDelete={canDelete ? () => onDelete(f) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${f.opportunityName}`}
          deleteLabel={`Delete ${f.opportunityName}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={rows}
      rowKey={(f) => f.id}
      empty="No funding opportunities match the current filters."
    />
  );
}
