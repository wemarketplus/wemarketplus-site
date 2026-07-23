import { Building2 } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
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
          <p className="font-bold text-[#111]">{a.unitNumber}</p>
          {a.unitType && <p className="text-[11px] text-[#667]">{a.unitType}</p>}
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
          <span className="inline-flex items-center gap-2">
            <Pill tone={APARTMENT_STATUS_PILL[a.status]}>{APARTMENT_STATUS_LABELS[a.status]}</Pill>
            <select
              aria-label="Change status"
              value={a.status}
              disabled={isMutating}
              onChange={(e) => onStatusChange(a, e.target.value)}
              className="rounded-md border border-[#d0dce8] bg-white px-1.5 py-1 text-[11px] text-[#111]"
            >
              {APARTMENT_STATUS_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </span>
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
