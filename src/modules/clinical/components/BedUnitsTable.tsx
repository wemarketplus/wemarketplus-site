import { BedDouble } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import {
  BED_UNIT_STATUS_LABELS,
  BED_UNIT_STATUS_PILL,
} from '../constants/clinicalTableConstants';
import { bedUnitLabel } from '../utils/bedUnitUtils';
import type { BedUnitRecord } from '../types/clinicalApiTypes';

interface BedUnitsTableProps {
  units: readonly BedUnitRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (unit: BedUnitRecord) => void;
  onDelete: (unit: BedUnitRecord) => void;
  onAdd?: () => void;
}

export function BedUnitsTable({
  units,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onAdd,
}: BedUnitsTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<BedUnitRecord>> = [
    {
      key: 'facility',
      header: 'Facility',
      cell: (u) => (
        <div>
          <p className="font-bold text-foreground">{u.facilityName}</p>
          <p className="text-[11px] text-muted">{u.bedType ?? '—'}</p>
        </div>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (u) => (
        <Pill tone={BED_UNIT_STATUS_PILL[u.status]}>{BED_UNIT_STATUS_LABELS[u.status]}</Pill>
      ),
    },
    { key: 'patient', header: 'Patient', cell: (u) => u.patientName ?? '—' },
    {
      key: 'notes',
      header: 'Notes',
      cell: (u) => <span className="text-muted">{u.notes ?? '—'}</span>,
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (u) => (
        <EntityRowActions
          onEdit={() => onEdit(u)}
          onDelete={canDelete ? () => onDelete(u) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${bedUnitLabel(u)}`}
          deleteLabel={`Delete ${bedUnitLabel(u)}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={units}
      rowKey={(u) => u.id}
      empty={
        hasFilters ? (
          'No bed units match the current filters.'
        ) : (
          <EmptyState
            icon={BedDouble}
            title="No bed units yet"
            description="Add a facility bed unit to start tracking availability and admissions."
            actionLabel={onAdd ? 'Add bed unit' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
