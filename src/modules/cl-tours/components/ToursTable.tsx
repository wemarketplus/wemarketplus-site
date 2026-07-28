import { CalendarClock } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import {
  TOUR_STATUS_LABELS,
  TOUR_STATUS_OPTIONS,
  TOUR_STATUS_PILL,
} from '../constants/clToursConstants';
import { tourWhen } from '../utils/clToursUtils';
import type { ClTourRecord } from '../types/clToursApiTypes';

interface ToursTableProps {
  tours: readonly ClTourRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  leadName: (id: string | null) => string;
  onEdit: (tour: ClTourRecord) => void;
  onDelete: (tour: ClTourRecord) => void;
  onStatusChange: (tour: ClTourRecord, status: string) => void;
  onAdd?: () => void;
}

export function ToursTable({
  tours,
  isMutating,
  hasFilters,
  leadName,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
}: ToursTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClTourRecord>> = [
    {
      key: 'lead',
      header: 'Lead',
      cell: (t) => <span className="font-bold text-[#111]">{leadName(t.leadId)}</span>,
    },
    { key: 'when', header: 'Scheduled', cell: (t) => tourWhen(t.scheduledAt) },
    {
      key: 'duration',
      header: 'Duration',
      cell: (t) => (t.durationMin ? `${t.durationMin} min` : '—'),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (t) => (
        <span className="inline-flex items-center gap-2">
          <Pill tone={TOUR_STATUS_PILL[t.status]}>{TOUR_STATUS_LABELS[t.status]}</Pill>
          <select
            aria-label={`Change status for tour`}
            value={t.status}
            disabled={isMutating}
            onChange={(e) => onStatusChange(t, e.target.value)}
            className="rounded-md border border-[#d0dce8] bg-white px-1.5 py-1 text-[11px] text-[#111]"
          >
            {TOUR_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </span>
      ),
    },
    { key: 'outcome', header: 'Outcome', cell: (t) => t.outcome ?? '—' },
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
          editLabel="Edit tour"
          deleteLabel="Delete tour"
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={tours}
      rowKey={(t) => t.id}
      empty={
        hasFilters ? (
          'No tours match the current filters.'
        ) : (
          <EmptyState
            icon={CalendarClock}
            title="No tours scheduled"
            description="Book a community tour for a prospective resident to move them down the pipeline."
            actionLabel={onAdd ? 'Book tour' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
