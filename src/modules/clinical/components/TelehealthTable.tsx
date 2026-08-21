import { Video } from 'lucide-react';
import { HL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDateTime } from '@/shared/utils/dateFormatter';
import {
  TELEHEALTH_STATUS_LABELS,
  TELEHEALTH_STATUS_PILL,
} from '../constants/clinicalTableConstants';
import { telehealthDuration, telehealthLabel } from '../utils/telehealthUtils';
import type { TelehealthSessionRecord } from '../types/clinicalApiTypes';

interface TelehealthTableProps {
  sessions: readonly TelehealthSessionRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (session: TelehealthSessionRecord) => void;
  onDelete: (session: TelehealthSessionRecord) => void;
  onAdd?: () => void;
}

export function TelehealthTable({
  sessions,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onAdd,
}: TelehealthTableProps) {
  // Delete is @Roles(Admin, Owner, Manager) on the backend; mirror that gate. This
  // read ADMIN_ONLY, which is stricter than the server and hid the action from a
  // Manager the API would have accepted.
  const { isAny } = useRole();
  const canDelete = isAny(HL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<TelehealthSessionRecord>> = [
    {
      key: 'patient',
      header: 'Patient',
      cell: (s) => (
        <div>
          <p className="font-bold text-foreground">{s.patientName}</p>
          <p className="text-[11px] text-muted">{s.providerName ?? '—'}</p>
        </div>
      ),
    },
    { key: 'type', header: 'Type', cell: (s) => s.sessionType ?? '—' },
    {
      key: 'scheduled',
      header: 'Scheduled',
      // scheduledAt is a timestamp — show the time, not just the day.
      cell: (s) => (s.scheduledAt ? formatDateTime(s.scheduledAt) : '—'),
    },
    {
      key: 'duration',
      header: 'Duration',
      // durationMin arrives as a string from TypeORM — coerced in telehealthDuration.
      cell: (s) => {
        const min = telehealthDuration(s);
        return min === null ? '—' : `${min} min`;
      },
    },
    {
      key: 'status',
      header: 'Status',
      cell: (s) => (
        <Pill tone={TELEHEALTH_STATUS_PILL[s.status]}>{TELEHEALTH_STATUS_LABELS[s.status]}</Pill>
      ),
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (s) => (
        <EntityRowActions
          onEdit={() => onEdit(s)}
          onDelete={canDelete ? () => onDelete(s) : undefined}
          disabled={isMutating}
          editLabel={`Edit ${telehealthLabel(s)}`}
          deleteLabel={`Delete ${telehealthLabel(s)}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={sessions}
      rowKey={(s) => s.id}
      empty={
        hasFilters ? (
          'No sessions match the current filters.'
        ) : (
          <EmptyState
            icon={Video}
            title="No telehealth sessions yet"
            description="Schedule a video visit with a patient or family to get started."
            actionLabel={onAdd ? 'Schedule session' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
