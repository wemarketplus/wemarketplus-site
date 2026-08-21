import { ClipboardList } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, StatusSelect, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { ClTaskRecord } from '@/modules/cl-outreach';
import {
  PRIORITY_LABELS,
  PRIORITY_PILL,
  STATUS_OPTIONS,
  STATUS_PILL,
} from '../constants/tasksConstants';

interface TasksTableProps {
  tasks: readonly ClTaskRecord[];
  /** Resolves an assignee id to a name — see useOpsStaff. */
  assigneeName: (id: string | null) => string;
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (task: ClTaskRecord) => void;
  onDelete: (task: ClTaskRecord) => void;
  onStatusChange: (task: ClTaskRecord, status: string) => void;
  onAdd?: () => void;
}

export function TasksTable({
  tasks,
  assigneeName,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
}: TasksTableProps) {
  // Delete is Admin/Owner-only on the backend for most CRUD; mirror that gate.
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClTaskRecord>> = [
    {
      key: 'title',
      header: 'Title',
      cell: (t) => (
        <div>
          <p className="font-bold text-foreground">{t.title}</p>
          {t.description ? (
            <p className="text-[11px] text-muted">{t.description}</p>
          ) : null}
        </div>
      ),
    },
    {
      key: 'priority',
      header: 'Priority',
      cell: (t) => <Pill tone={PRIORITY_PILL[t.priority]}>{PRIORITY_LABELS[t.priority]}</Pill>,
    },
    {
      key: 'status',
      header: 'Status',
      // One control, not a badge beside a dropdown of the same value — see
      // StatusSelect. The PATCH behind `onStatusChange` is unchanged.
      cell: (t) => (
        <StatusSelect
          value={t.status}
          tone={STATUS_PILL[t.status]}
          options={STATUS_OPTIONS}
          disabled={isMutating}
          onChange={(status) => onStatusChange(t, status)}
          aria-label={`Change status for ${t.title}`}
        />
      ),
    },
    {
      key: 'assignee',
      header: 'Assigned to',
      cell: (t) => assigneeName(t.assignedTo),
    },
    {
      key: 'dueDate',
      header: 'Due date',
      cell: (t) => (t.dueDate ? formatDate(t.dueDate) : '—'),
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
          editLabel={`Edit ${t.title}`}
          deleteLabel={`Delete ${t.title}`}
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
          'No tasks match the current filters.'
        ) : (
          <EmptyState
            icon={ClipboardList}
            title="No tasks yet"
            description="Add your first task to track outreach follow-ups and to-dos."
            actionLabel={onAdd ? 'Add task' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
