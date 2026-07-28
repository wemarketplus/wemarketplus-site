import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { AGREEMENT_STATUS_LABELS } from '../constants/agreementsConstants';
import type { AgreementRecord } from '../types/agreementsTypes';

interface AgreementsTableProps {
  rows: readonly AgreementRecord[];
  isMutating: boolean;
  onEdit: (record: AgreementRecord) => void;
  onDelete: (record: AgreementRecord) => void;
}

export function AgreementsTable({ rows, isMutating, onEdit, onDelete }: AgreementsTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate on the action.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<AgreementRecord>> = [
    {
      key: 'agreement',
      header: 'Agreement',
      cell: (a) => (
        <div>
          <p className="font-bold text-foreground">{a.agreementName}</p>
          {a.companyName && <p className="text-[11px] text-muted">{a.companyName}</p>}
        </div>
      ),
    },
    { key: 'status', header: 'Status', cell: (a) => AGREEMENT_STATUS_LABELS[a.status] ?? a.status },
    { key: 'type', header: 'Type', cell: (a) => a.agreementType ?? '—' },
    {
      key: 'value',
      header: 'Value',
      cell: (a) => (a.value != null ? `$${a.value.toLocaleString()}` : '—'),
    },
    {
      key: 'expires',
      header: 'Expires',
      cell: (a) => (a.expirationDate ? formatDate(a.expirationDate) : '—'),
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (a) => (
        <EntityRowActions
          onEdit={() => onEdit(a)}
          onDelete={canDelete ? () => onDelete(a) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${a.agreementName}`}
          deleteLabel={`Delete ${a.agreementName}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={rows}
      rowKey={(a) => a.id}
      empty="No agreements match the current filters."
    />
  );
}
