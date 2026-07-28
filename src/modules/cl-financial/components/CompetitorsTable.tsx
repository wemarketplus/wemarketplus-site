import { Swords } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatUsd } from '../utils/financialFormat';
import { num } from '../utils/clFinancialMappers';
import type { ClCompetitorRecord } from '../types/clFinancialApiTypes';

interface CompetitorsTableProps {
  competitors: readonly ClCompetitorRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (c: ClCompetitorRecord) => void;
  onDelete: (c: ClCompetitorRecord) => void;
  onAdd?: () => void;
}

const rate = (v: number | null) => (v != null ? formatUsd(num(v)) : '—');

export function CompetitorsTable({
  competitors,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onAdd,
}: CompetitorsTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClCompetitorRecord>> = [
    {
      key: 'name',
      header: 'Community',
      cell: (c) => (
        <div>
          <p className="font-bold text-foreground">{c.name}</p>
          {c.city && <p className="text-[11px] text-muted">{c.city}</p>}
        </div>
      ),
    },
    {
      key: 'distance',
      header: 'Distance',
      cell: (c) => (c.distanceMiles != null ? `${num(c.distanceMiles).toFixed(1)} mi` : '—'),
    },
    { key: 'il', header: 'IL', cell: (c) => rate(c.rateIl) },
    { key: 'al', header: 'AL', cell: (c) => rate(c.rateAl) },
    { key: 'mc', header: 'MC', cell: (c) => rate(c.rateMc) },
    {
      key: 'occ',
      header: 'Occupancy',
      cell: (c) => (c.occupancyPct != null ? `${num(c.occupancyPct).toFixed(0)}%` : '—'),
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
          editLabel="Edit competitor"
          deleteLabel="Delete competitor"
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={competitors}
      rowKey={(c) => c.id}
      empty={
        hasFilters ? (
          'No competitors match the current filters.'
        ) : (
          <EmptyState
            icon={Swords}
            title="No competitor intel yet"
            description="Track nearby communities' rates and occupancy to price competitively."
            actionLabel={onAdd ? 'Add competitor' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
