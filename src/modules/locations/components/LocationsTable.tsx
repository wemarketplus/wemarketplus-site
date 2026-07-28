import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { LOCATION_STATUS_LABELS } from '../constants/locationsConstants';
import type { LocationRecord } from '../types/locationsTypes';

interface LocationsTableProps {
  locations: readonly LocationRecord[];
  isMutating: boolean;
  onEdit: (location: LocationRecord) => void;
  onDelete: (location: LocationRecord) => void;
}

export function LocationsTable({ locations, isMutating, onEdit, onDelete }: LocationsTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate on the action.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<LocationRecord>> = [
    {
      key: 'location',
      header: 'Location',
      cell: (l) => (
        <div>
          <p className="font-bold text-foreground">{l.locationName}</p>
          {l.address && <p className="text-[11px] text-muted">{l.address}</p>}
        </div>
      ),
    },
    {
      key: 'place',
      header: 'City / State',
      cell: (l) => [l.city, l.state].filter(Boolean).join(', ') || '—',
    },
    { key: 'status', header: 'Status', cell: (l) => LOCATION_STATUS_LABELS[l.status] ?? l.status },
    {
      key: 'employees',
      header: 'Employees',
      cell: (l) => (l.employeeCount != null ? l.employeeCount.toLocaleString() : '—'),
    },
    { key: 'created', header: 'Added', cell: (l) => formatDate(l.createdAt) },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (l) => (
        <EntityRowActions
          onEdit={() => onEdit(l)}
          onDelete={canDelete ? () => onDelete(l) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${l.locationName}`}
          deleteLabel={`Delete ${l.locationName}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={locations}
      rowKey={(l) => l.id}
      empty="No locations match the current filters."
    />
  );
}
