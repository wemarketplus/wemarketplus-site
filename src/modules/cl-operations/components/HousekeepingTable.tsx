import { Sparkles } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import {
  HOUSEKEEPING_STATUS_LABELS,
  HOUSEKEEPING_STATUS_OPTIONS,
  HOUSEKEEPING_STATUS_PILL,
} from '../constants/clOperationsConstants';
import type { ClHousekeepingTaskRecord } from '../types/clOperationsApiTypes';

interface HousekeepingTableProps {
  tasks: readonly ClHousekeepingTaskRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (t: ClHousekeepingTaskRecord) => void;
  onDelete: (t: ClHousekeepingTaskRecord) => void;
  onStatusChange: (t: ClHousekeepingTaskRecord, status: string) => void;
  onAdd?: () => void;
}

export function HousekeepingTable({
  tasks,
  isMutating,
  hasFilters,
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
      cell: (t) => <span className="font-bold text-[#111]">{t.taskType}</span>,
    },
    { key: 'area', header: 'Unit / area', cell: (t) => t.area ?? '—' },
    {
      key: 'status',
      header: 'Status',
      cell: (t) => (
        <span className="inline-flex items-center gap-2">
          <Pill tone={HOUSEKEEPING_STATUS_PILL[t.status]}>
            {HOUSEKEEPING_STATUS_LABELS[t.status]}
          </Pill>
          <select
            aria-label="Change status"
            value={t.status}
            disabled={isMutating}
            onChange={(e) => onStatusChange(t, e.target.value)}
            className="rounded-md border border-[#d0dce8] bg-white px-1.5 py-1 text-[11px] text-[#111]"
          >
            {HOUSEKEEPING_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </span>
      ),
    },
    {
      key: 'due',
      header: 'Due',
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
