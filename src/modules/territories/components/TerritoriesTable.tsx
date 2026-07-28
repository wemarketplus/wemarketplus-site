import { useRole } from '@/shared/rbac';
import { Role } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { TERRITORY_PRIORITY_LABELS } from '../constants/territoriesConstants';
import type { TerritoryRecord } from '../types/territoriesTypes';

interface TerritoriesTableProps {
  territories: readonly TerritoryRecord[];
  isMutating: boolean;
  onEdit: (territory: TerritoryRecord) => void;
  onDelete: (territory: TerritoryRecord) => void;
}

// Edit + delete are Admin/Owner/Manager on the backend; mirror that gate.
const MANAGE_ROLES: readonly Role[] = [Role.SuperAdmin, Role.Admin, Role.Owner, Role.Manager];

export function TerritoriesTable({
  territories,
  isMutating,
  onEdit,
  onDelete,
}: TerritoriesTableProps) {
  const { isAny } = useRole();
  const canManage = isAny(MANAGE_ROLES);

  const columns: ReadonlyArray<Column<TerritoryRecord>> = [
    {
      key: 'name',
      header: 'Territory',
      cell: (t) => <p className="font-bold text-foreground">{t.name}</p>,
    },
    {
      key: 'place',
      header: 'City / State',
      cell: (t) => [t.city, t.state].filter(Boolean).join(', ') || '—',
    },
    {
      key: 'priority',
      header: 'Priority',
      cell: (t) => TERRITORY_PRIORITY_LABELS[t.priority] ?? t.priority,
    },
    {
      key: 'zips',
      header: 'Zip codes',
      cell: (t) => (t.zipCodes && t.zipCodes.length ? t.zipCodes.length.toLocaleString() : '—'),
    },
    { key: 'created', header: 'Added', cell: (t) => formatDate(t.createdAt) },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (t) => (
        <EntityRowActions
          onEdit={canManage ? () => onEdit(t) : undefined}
          onDelete={canManage ? () => onDelete(t) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${t.name}`}
          deleteLabel={`Delete ${t.name}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={territories}
      rowKey={(t) => t.id}
      empty="No territories match the current filters."
    />
  );
}
