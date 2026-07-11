import { ClipboardCheck } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  MAKE_READY_STATUS_LABELS,
  MAKE_READY_STATUS_OPTIONS,
  MAKE_READY_STATUS_PILL,
} from '../constants/clOperationsConstants';
import type { ClMakeReadyTaskRecord } from '../types/clOperationsApiTypes';

interface MakeReadyTableProps {
  tasks: readonly ClMakeReadyTaskRecord[];
  unitLabel: (apartmentId: string | null) => string;
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
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
}: MakeReadyTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ClMakeReadyTaskRecord>> = [
    {
      key: 'task',
      header: 'Task',
      cell: (t) => <span className="font-bold text-[#111]">{t.taskName}</span>,
    },
    { key: 'unit', header: 'Unit', cell: (t) => unitLabel(t.apartmentId) },
    {
      key: 'status',
      header: 'Status',
      cell: (t) => (
        <span className="inline-flex items-center gap-2">
          <Pill tone={MAKE_READY_STATUS_PILL[t.status]}>{MAKE_READY_STATUS_LABELS[t.status]}</Pill>
          <select
            aria-label="Change status"
            value={t.status}
            disabled={isMutating}
            onChange={(e) => onStatusChange(t, e.target.value)}
            className="rounded-md border border-[#d0dce8] bg-white px-1.5 py-1 text-[11px] text-[#111]"
          >
            {MAKE_READY_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </span>
      ),
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
