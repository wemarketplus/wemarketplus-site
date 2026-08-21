import { Building2 } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, StatusSelect, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import {
  APARTMENT_STATUS_LABELS,
  APARTMENT_STATUS_OPTIONS,
  APARTMENT_STATUS_PILL,
} from '../constants/clOperationsConstants';
import type { ClApartmentRecord } from '../types/clOperationsApiTypes';

interface ApartmentsTableProps {
  apartments: readonly ClApartmentRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit?: (a: ClApartmentRecord) => void;
  onDelete?: (a: ClApartmentRecord) => void;
  onStatusChange?: (a: ClApartmentRecord, status: string) => void;
  onAdd?: () => void;
  // Unit Status (Maintenance/Housekeeping, Max tier): a plain read-only render
  // of the same data — no status editing, no row actions, no add.
  readOnly?: boolean;
}

export function ApartmentsTable({
  apartments,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
  readOnly = false,
}: ApartmentsTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClApartmentRecord>> = [
    {
      key: 'unit',
      header: 'Unit',
      cell: (a) => (
        <div>
          <p className="font-bold text-foreground">{a.unitNumber}</p>
          {a.unitType && <p className="text-[11px] text-muted">{a.unitType}</p>}
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (a) =>
        readOnly || !onStatusChange ? (
          <Pill tone={APARTMENT_STATUS_PILL[a.status]}>{APARTMENT_STATUS_LABELS[a.status]}</Pill>
        ) : (
          // Editable: ONE control that is both the badge and the picker, so the
          // status is not stated twice. The read-only branch above stays a plain
          // Pill — same shape and tone, minus the affordance.
          <StatusSelect
            value={a.status}
            tone={APARTMENT_STATUS_PILL[a.status]}
            options={APARTMENT_STATUS_OPTIONS}
            disabled={isMutating}
            onChange={(status) => onStatusChange(a, status)}
            aria-label="Change status"
          />
        ),
    },
    { key: 'resident', header: 'Resident', cell: (a) => a.residentName ?? '—' },
    {
      key: 'rate',
      header: 'Rate',
      cell: (a) => (a.monthlyRate != null ? `$${Number(a.monthlyRate).toLocaleString()}/mo` : '—'),
    },
    ...(readOnly
      ? []
      : [
          {
            key: 'actions',
            header: '',
            headerClassName: 'w-20',
            className: 'text-right',
            cell: (a: ClApartmentRecord) => (
              <EntityRowActions
                onEdit={onEdit ? () => onEdit(a) : undefined}
                onDelete={canDelete && onDelete ? () => onDelete(a) : undefined}
                disabled={isMutating}
                editLabel="Edit unit"
                deleteLabel="Delete unit"
              />
            ),
          },
        ]),
  ];

  return (
    <DataTable
      columns={columns}
      rows={apartments}
      rowKey={(a) => a.id}
      empty={
        hasFilters ? (
          'No units match the current filters.'
        ) : (
          <EmptyState
            icon={Building2}
            title="No units yet"
            description="Add apartments to a community to track occupancy and turn status."
            actionLabel={onAdd ? 'Add unit' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
