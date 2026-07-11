import { Building2 } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
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
  onEdit: (a: ClApartmentRecord) => void;
  onDelete: (a: ClApartmentRecord) => void;
  onStatusChange: (a: ClApartmentRecord, status: string) => void;
  onAdd?: () => void;
}

export function ApartmentsTable({
  apartments,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
}: ApartmentsTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

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
      cell: (a) => (
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
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (a) => (
        <EntityRowActions
          onEdit={() => onEdit(a)}
          onDelete={canDelete ? () => onDelete(a) : undefined}
          disabled={isMutating}
          editLabel="Edit unit"
          deleteLabel="Delete unit"
        />
      ),
    },
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
