import { RotateCcw, Sparkles } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, StatusSelect, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { HOUSEKEEPING_STATUS } from '../constants/clOperationsApiConstants';
import {
  HOUSEKEEPING_STATUS_OPTIONS,
  HOUSEKEEPING_STATUS_PILL,
} from '../constants/clOperationsConstants';
import type { ClHousekeepingTaskRecord } from '../types/clOperationsApiTypes';

interface HousekeepingTableProps {
  tasks: readonly ClHousekeepingTaskRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  /** Resolves `assignedTo` to a name. See useOpsStaff. */
  assigneeName: (id: string | null) => string;
  onEdit: (t: ClHousekeepingTaskRecord) => void;
  onDelete: (t: ClHousekeepingTaskRecord) => void;
  onStatusChange: (t: ClHousekeepingTaskRecord, status: string) => void;
  onAdd?: () => void;
}

/**
 * A task nobody owes any more: done, or deliberately skipped. Mirrors the backend's
 * CLOSED_HOUSEKEEPING_STATUSES — a skipped clean is closed, not outstanding.
 */
const isFinished = (status: ClHousekeepingTaskRecord['status']): boolean =>
  status === HOUSEKEEPING_STATUS.Completed ||
  status === HOUSEKEEPING_STATUS.Skipped;

export function HousekeepingTable({
  tasks,
  isMutating,
  hasFilters,
  assigneeName,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
}: HousekeepingTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClHousekeepingTaskRecord>> = [
    {
      key: 'task',
      header: 'Task',
      cell: (t) => <span className="font-bold text-foreground">{t.taskType}</span>,
    },
    { key: 'area', header: 'Unit / area', cell: (t) => t.area ?? '—' },
    {
      key: 'status',
      header: 'Status',
      // One control, not a badge beside a dropdown of the same value.
      cell: (t) => (
        <StatusSelect
          value={t.status}
          tone={HOUSEKEEPING_STATUS_PILL[t.status]}
          options={HOUSEKEEPING_STATUS_OPTIONS}
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
    {
      key: 'due',
      header: 'Due',
      cell: (t) => (t.dueDate ? formatDate(t.dueDate) : '—'),
    },
    /**
     * REOPEN — the guide's step 3, "or Reopen if something needs to be redone".
     *
     * A named action rather than "set the dropdown back to Not started": redoing a
     * clean is a decision with a reason behind it (an inspection failed, a resident
     * complained), and it is the one status move a cleaner makes that is not simply
     * the next step forward. The dropdown can still express it; this makes it one
     * click and gives it the word the guide uses.
     *
     * Only rendered on a FINISHED task. On a pending or in-progress row there is
     * nothing to reopen, and a button that does nothing on most rows teaches people
     * to stop reading the column.
     */
    {
      key: 'reopen',
      header: '',
      headerClassName: 'w-24',
      cell: (t) =>
        isFinished(t.status) ? (
          <button
            type="button"
            disabled={isMutating}
            onClick={() => onStatusChange(t, HOUSEKEEPING_STATUS.Pending)}
            className="inline-flex items-center gap-1 text-[11px] font-semibold text-muted underline-offset-2 hover:text-foreground hover:underline disabled:opacity-50"
          >
            <RotateCcw className="h-3 w-3" /> Reopen
          </button>
        ) : null,
    },
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
          'No housekeeping tasks match the current filters.'
        ) : (
          <EmptyState
            icon={Sparkles}
            title="No housekeeping tasks yet"
            description="Assign a cleaning or make-ready task to keep units turn-ready."
            actionLabel={onAdd ? 'Assign task' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
