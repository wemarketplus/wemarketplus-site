import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { APPLICATION_STATUS_LABELS } from '../constants/applicationsConstants';
import type { ApplicationRecord } from '../types/applicationsTypes';

interface ApplicationsTableProps {
  rows: readonly ApplicationRecord[];
  isMutating: boolean;
  onEdit: (record: ApplicationRecord) => void;
  onDelete: (record: ApplicationRecord) => void;
}

const money = (v: number | null) => (v != null ? `$${v.toLocaleString()}` : '—');

export function ApplicationsTable({ rows, isMutating, onEdit, onDelete }: ApplicationsTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate on the action.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ApplicationRecord>> = [
    {
      key: 'application',
      header: 'Application',
      cell: (a) => (
        <p className="font-bold text-foreground">{a.applicationNumber ?? a.id.slice(0, 8)}</p>
      ),
    },
    { key: 'status', header: 'Status', cell: (a) => APPLICATION_STATUS_LABELS[a.status] ?? a.status },
    { key: 'requested', header: 'Requested', cell: (a) => money(a.awardAmountRequested) },
    { key: 'approved', header: 'Approved', cell: (a) => money(a.awardAmountApproved) },
    {
      key: 'submitted',
      header: 'Submitted',
      cell: (a) => (a.submissionDate ? formatDate(a.submissionDate) : '—'),
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
          editLabel={`Edit application ${a.applicationNumber ?? a.id}`}
          deleteLabel={`Delete application ${a.applicationNumber ?? a.id}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={rows}
      rowKey={(a) => a.id}
      empty="No applications match the current filters."
    />
  );
}
