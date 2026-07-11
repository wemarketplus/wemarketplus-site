import { ClipboardList } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import type { ClTaskRecord } from '@/modules/cl-outreach';
import {
  PRIORITY_LABELS,
  PRIORITY_PILL,
  STATUS_LABELS,
  STATUS_OPTIONS,
  STATUS_PILL,
} from '../constants/tasksConstants';

interface TasksTableProps {
  tasks: readonly ClTaskRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (task: ClTaskRecord) => void;
  onDelete: (task: ClTaskRecord) => void;
  onStatusChange: (task: ClTaskRecord, status: string) => void;
  onAdd?: () => void;
}

export function TasksTable({
  tasks,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
}: TasksTableProps) {
  // Delete is Admin/Owner-only on the backend for most CRUD; mirror that gate.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ClTaskRecord>> = [
    {
      key: 'title',
      header: 'Title',
      cell: (t) => (
        <div>
          <p className="font-bold text-[#111]">{t.title}</p>
          {t.description ? (
            <p className="text-[11px] text-[#667]">{t.description}</p>
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
      cell: (t) => (
        <span className="inline-flex items-center gap-2">
          <Pill tone={STATUS_PILL[t.status]}>{STATUS_LABELS[t.status]}</Pill>
          <select
            aria-label={`Change status for ${t.title}`}
            value={t.status}
            disabled={isMutating}
            onChange={(e) => onStatusChange(t, e.target.value)}
            className="rounded-md border border-[#d0dce8] bg-white px-1.5 py-1 text-[11px] text-[#111]"
          >
            {STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </span>
      ),
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
