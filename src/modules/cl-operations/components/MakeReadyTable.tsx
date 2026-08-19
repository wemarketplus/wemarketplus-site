import { ClipboardCheck } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, StatusSelect, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  MAKE_READY_STATUS_OPTIONS,
  MAKE_READY_STATUS_PILL,
} from '../constants/clOperationsConstants';
import type { ClMakeReadyTaskRecord } from '../types/clOperationsApiTypes';

interface MakeReadyTableProps {
  tasks: readonly ClMakeReadyTaskRecord[];
  unitLabel: (apartmentId: string | null) => string;
  /** Resolves an assignee id to a name — see useOpsStaff. */
  assigneeName: (id: string | null) => string;
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (t: ClMakeReadyTaskRecord) => void;
  onDelete: (t: ClMakeReadyTaskRecord) => void;
  onStatusChange: (t: ClMakeReadyTaskRecord, status: string) => void;
  onAdd?: () => void;
}

export function MakeReadyTable({
  tasks,
  unitLabel,
  assigneeName,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
}: MakeReadyTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClMakeReadyTaskRecord>> = [
    {
      key: 'task',
      header: 'Task',
      cell: (t) => <span className="font-bold text-foreground">{t.taskName}</span>,
    },
    { key: 'unit', header: 'Unit', cell: (t) => unitLabel(t.apartmentId) },
    {
      key: 'status',
      header: 'Status',
      // One control, not a badge beside a dropdown of the same value.
      cell: (t) => (
        <StatusSelect
          value={t.status}
          tone={MAKE_READY_STATUS_PILL[t.status]}
          options={MAKE_READY_STATUS_OPTIONS}
          disabled={isMutating}
          onChange={(status) => onStatusChange(t, status)}
          aria-label="Change status"
        />
      ),
    },
    {
      key: 'assignee',
      header: 'Assigned to',
      cell: (t) => assigneeName(t.assignedTo),
    },
    { key: 'due', header: 'Due', cell: (t) => (t.dueDate ? formatDate(t.dueDate) : '—') },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (t) => (
        <EntityRowActions
          onEdit={() => onEdit(t)}
          onDelete={canDelete ? () => onDelete(t) : undefined}
          disabled={isMutating}
          editLabel="Edit task"
          deleteLabel="Delete task"
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={tasks}
      rowKey={(t) => t.id}
      empty={
        hasFilters ? (
          'No make-ready tasks match the current filters.'
        ) : (
          <EmptyState
            icon={ClipboardCheck}
            title="No make-ready tasks yet"
            description="Add turn tasks to a unit so it is show-ready for the next resident."
            actionLabel={onAdd ? 'Add task' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
