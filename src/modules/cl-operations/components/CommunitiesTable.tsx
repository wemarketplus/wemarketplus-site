import { Building } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import type { ClCommunityRecord } from '../types/clOperationsApiTypes';

interface CommunitiesTableProps {
  communities: readonly ClCommunityRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (c: ClCommunityRecord) => void;
  onDelete: (c: ClCommunityRecord) => void;
  onAdd?: () => void;
}

export function CommunitiesTable({
  communities,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onAdd,
}: CommunitiesTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ClCommunityRecord>> = [
    {
      key: 'name',
      header: 'Community',
      cell: (c) => <span className="font-bold text-[#111]">{c.name}</span>,
    },
    {
      key: 'location',
      header: 'Location',
      cell: (c) => [c.city, c.state].filter(Boolean).join(', ') || '—',
    },
    { key: 'phone', header: 'Phone', cell: (c) => c.phone ?? '—' },
    {
      key: 'units',
      header: 'Units',
      cell: (c) => (c.totalUnits != null ? Number(c.totalUnits) : '—'),
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (c) => (
        <EntityRowActions
          onEdit={() => onEdit(c)}
          onDelete={canDelete ? () => onDelete(c) : undefined}
          disabled={isMutating}
          editLabel="Edit community"
          deleteLabel="Delete community"
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={communities}
      rowKey={(c) => c.id}
      empty={
        hasFilters ? (
          'No communities match the current filters.'
        ) : (
          <EmptyState
            icon={Building}
            title="No communities yet"
            description="Add your senior-living community first — apartments, make-ready, and occupancy all live inside a community."
            actionLabel={onAdd ? 'Add community' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
