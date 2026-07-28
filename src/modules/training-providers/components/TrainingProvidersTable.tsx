import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, type Column } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { TRAINING_PROVIDER_STATUS_LABELS } from '../constants/trainingConstants';
import type { TrainingProviderRecord } from '../types/trainingTypes';

interface TrainingProvidersTableProps {
  providers: readonly TrainingProviderRecord[];
  isMutating: boolean;
  onEdit: (provider: TrainingProviderRecord) => void;
  onDelete: (provider: TrainingProviderRecord) => void;
}

export function TrainingProvidersTable({
  providers,
  isMutating,
  onEdit,
  onDelete,
}: TrainingProvidersTableProps) {
  // Delete is Admin/Owner-only on the backend; mirror that gate on the action.
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<TrainingProviderRecord>> = [
    {
      key: 'provider',
      header: 'Provider',
      cell: (p) => (
        <div>
          <p className="font-bold text-foreground">{p.name}</p>
          {p.providerType && <p className="text-[11px] text-muted">{p.providerType}</p>}
        </div>
      ),
    },
    { key: 'email', header: 'Contact', cell: (p) => p.contactEmail ?? p.contactPhone ?? '—' },
    { key: 'state', header: 'State', cell: (p) => p.state ?? '—' },
    {
      key: 'status',
      header: 'Status',
      cell: (p) => TRAINING_PROVIDER_STATUS_LABELS[p.status] ?? p.status,
    },
    { key: 'created', header: 'Added', cell: (p) => formatDate(p.createdAt) },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (p) => (
        <EntityRowActions
          onEdit={() => onEdit(p)}
          onDelete={canDelete ? () => onDelete(p) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${p.name}`}
          deleteLabel={`Delete ${p.name}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={providers}
      rowKey={(p) => p.id}
      empty="No training providers match the current filters."
    />
  );
}
