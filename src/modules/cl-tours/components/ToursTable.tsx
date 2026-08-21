import { CalendarClock, MapPin } from 'lucide-react';
import { formatCoords } from '@/modules/geocoding';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, StatusSelect, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import {
  TOUR_STATUS_OPTIONS,
  TOUR_STATUS_PILL,
} from '../constants/clToursConstants';
import { tourEndpoint, tourWhen } from '../utils/clToursUtils';
import type { ClTourRecord } from '../types/clToursApiTypes';

interface ToursTableProps {
  tours: readonly ClTourRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  leadName: (id: string | null) => string;
  guideName: (id: string | null) => string;
  onEdit: (tour: ClTourRecord) => void;
  onDelete: (tour: ClTourRecord) => void;
  onStatusChange: (tour: ClTourRecord, status: string) => void;
  /** Stamp or clear `confirmedAt` — the guide's Confirm action. */
  onConfirmToggle: (tour: ClTourRecord) => void;
  onAdd?: () => void;
}

/**
 * One endpoint as a table cell: the name a person reads, with a pin when the place
 * was actually pinned on the map.
 *
 * The LABEL is what goes down the column — a lat/lng pair per row would bury the
 * four names a guide is scanning for — so the coordinates ride in the pin's
 * tooltip, exactly as the mileage table's Route cell does. Truncated with a
 * width cap because a geocoded label can be a full postal address and the
 * scheduler already carries eight other columns.
 */
function endpointCell(tour: ClTourRecord, side: 'from' | 'to') {
  const place = tourEndpoint(tour, side);
  if (!place.label) return '—';
  return (
    <span className="inline-flex max-w-[150px] items-center gap-1.5">
      <span className="truncate" title={place.label}>
        {place.label}
      </span>
      {place.coords && (
        <span title={formatCoords(place.coords)}>
          <MapPin
            className="h-3 w-3 shrink-0 text-primary"
            aria-label="Pinned on a map"
          />
        </span>
      )}
    </span>
  );
}

export function ToursTable({
  tours,
  isMutating,
  hasFilters,
  leadName,
  guideName,
  onEdit,
  onDelete,
  onStatusChange,
  onConfirmToggle,
  onAdd,
}: ToursTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClTourRecord>> = [
    {
      key: 'lead',
      header: 'Lead',
      cell: (t) => <span className="font-bold text-foreground">{leadName(t.leadId)}</span>,
    },
    { key: 'when', header: 'Scheduled', cell: (t) => tourWhen(t.scheduledAt) },
    { key: 'guide', header: 'Guide', cell: (t) => guideName(t.guideUserId) },
    // WHERE the tour runs: the pickup point and the community being shown. Next
    // to Guide rather than at the end because "who is showing which building,
    // and are they collecting anyone first" is one thought, and the answer used
    // to live nowhere on this screen at all.
    { key: 'from', header: 'From', cell: (t) => endpointCell(t, 'from') },
    { key: 'to', header: 'To', cell: (t) => endpointCell(t, 'to') },
    /**
     * Confirmation — its own column, because it is its own axis.
     *
     * Green "Confirmed" once the family has acknowledged, orange "Pending" with a
     * Confirm button until then, exactly as the end-user guide describes. It is
     * NOT folded into Status: a tour can be confirmed AND completed, and the
     * status enum can only ever say one thing at a time.
     *
     * Confirm stays available on a completed or cancelled tour rather than being
     * hidden — a marketer confirming yesterday's tour after the fact is recording
     * history, and the button is also the only way to undo a mis-click.
     */
    {
      key: 'confirmed',
      header: 'Confirmation',
      cell: (t) => (
        <span className="inline-flex items-center gap-2">
          {t.confirmedAt ? (
            <Pill tone="g">Confirmed</Pill>
          ) : (
            <Pill tone="y">Pending</Pill>
          )}
          <button
            type="button"
            disabled={isMutating}
            onClick={() => onConfirmToggle(t)}
            className="text-[11px] font-semibold text-muted underline-offset-2 hover:text-foreground hover:underline disabled:opacity-50"
          >
            {t.confirmedAt ? 'Undo' : 'Confirm'}
          </button>
        </span>
      ),
    },
    {
      key: 'duration',
      header: 'Duration',
      cell: (t) => (t.durationMin ? `${t.durationMin} min` : '—'),
    },
    /**
     * Status — ONE control, not a badge plus a dropdown saying the same thing.
     *
     * The badge and the select were both bound to `t.status`, so each row
     * printed its status twice. <StatusSelect> is the badge and the picker in
     * one element: same pill colour for scanning the column, still changeable
     * in place without opening the edit modal (the PATCH behind
     * `onStatusChange` is untouched).
     */
    {
      key: 'status',
      header: 'Status',
      cell: (t) => (
        <StatusSelect
          value={t.status}
          tone={TOUR_STATUS_PILL[t.status]}
          options={TOUR_STATUS_OPTIONS}
          disabled={isMutating}
          onChange={(status) => onStatusChange(t, status)}
          aria-label={`Change status for the tour with ${leadName(t.leadId)}`}
        />
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
