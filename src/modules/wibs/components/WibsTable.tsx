import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { WIB_STATUS_LABELS } from '../constants/wibsConstants';
import type { WibRecord } from '../types/wibsTypes';

interface WibsTableProps {
  rows: readonly WibRecord[];
  isMutating: boolean;
  onEdit: (record: WibRecord) => void;
  onDelete: (record: WibRecord) => void;
}

export function WibsTable({ rows, isMutating, onEdit, onDelete }: WibsTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate on the action.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<WibRecord>> = [
    {
      key: 'wib',
      header: 'WIB',
      cell: (w) => (
        <div>
          <p className="font-bold text-[#111]">{w.wibName}</p>
          {w.shortName && <p className="text-[11px] text-[#667]">{w.shortName}</p>}
        </div>
      ),
    },
    { key: 'state', header: 'State', cell: (w) => w.state ?? '—' },
    { key: 'status', header: 'Status', cell: (w) => WIB_STATUS_LABELS[w.status] ?? w.status },
    { key: 'email', header: 'Email', cell: (w) => w.wibEmail ?? '—' },
    { key: 'priority', header: 'Priority', cell: (w) => String(w.callPriorityScore) },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (w) => (
        <EntityRowActions
          onEdit={() => onEdit(w)}
          onDelete={canDelete ? () => onDelete(w) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${w.wibName}`}
          deleteLabel={`Delete ${w.wibName}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={rows}
      rowKey={(w) => w.id}
      empty="No WIBs match the current filters."
    />
  );
}
