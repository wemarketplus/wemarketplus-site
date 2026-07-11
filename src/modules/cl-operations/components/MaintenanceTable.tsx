import { Wrench } from 'lucide-react';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { EmptyState } from '@/shared/ui/feedback';
import { EntityRowActions } from '@/shared/ui/entity';
import {
  MAINTENANCE_STATUS_LABELS,
  MAINTENANCE_STATUS_OPTIONS,
  MAINTENANCE_STATUS_PILL,
  TICKET_PRIORITY_LABELS,
  TICKET_PRIORITY_PILL,
} from '../constants/clOperationsConstants';
import type { ClMaintenanceTicketRecord } from '../types/clOperationsApiTypes';

interface MaintenanceTableProps {
  tickets: readonly ClMaintenanceTicketRecord[];
  isMutating: boolean;
  hasFilters: boolean;
  onEdit: (t: ClMaintenanceTicketRecord) => void;
  onDelete: (t: ClMaintenanceTicketRecord) => void;
  onStatusChange: (t: ClMaintenanceTicketRecord, status: string) => void;
  onAdd?: () => void;
}

export function MaintenanceTable({
  tickets,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
}: MaintenanceTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(ADMIN_ONLY);

  const columns: ReadonlyArray<Column<ClMaintenanceTicketRecord>> = [
    {
      key: 'ticket',
      header: 'Ticket',
      cell: (t) => <span className="font-bold text-[#111]">{t.ticketNumber ?? '—'}</span>,
    },
    {
      key: 'issue',
      header: 'Issue',
      cell: (t) => (
        <div>
          <p className="text-[#111]">{t.issue}</p>
          {t.reporterName && <p className="text-[11px] text-[#667]">{t.reporterName}</p>}
        </div>
      ),
    },
    {
      key: 'priority',
      header: 'Priority',
      cell: (t) => (
        <Pill tone={TICKET_PRIORITY_PILL[t.priority]}>{TICKET_PRIORITY_LABELS[t.priority]}</Pill>
      ),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (t) => (
        <span className="inline-flex items-center gap-2">
          <Pill tone={MAINTENANCE_STATUS_PILL[t.status]}>
            {MAINTENANCE_STATUS_LABELS[t.status]}
          </Pill>
          <select
            aria-label="Change status"
            value={t.status}
            disabled={isMutating}
            onChange={(e) => onStatusChange(t, e.target.value)}
            className="rounded-md border border-[#d0dce8] bg-white px-1.5 py-1 text-[11px] text-[#111]"
          >
            {MAINTENANCE_STATUS_OPTIONS.map((o) => (
              <option key={o.value} value={o.value}>
                {o.label}
              </option>
            ))}
          </select>
        </span>
      ),
    },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (t) => (
        <EntityRowActions
          onEdit={() => onEdit(t)}
          onDelete={canDelete ? () => onDelete(t) : undefined}
          disabled={isMutating}
          editLabel="Edit ticket"
          deleteLabel="Delete ticket"
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={tickets}
      rowKey={(t) => t.id}
      empty={
        hasFilters ? (
          'No tickets match the current filters.'
        ) : (
          <EmptyState
            icon={Wrench}
            title="No work orders yet"
            description="Log a maintenance ticket when a unit needs a repair."
            actionLabel={onAdd ? 'New ticket' : undefined}
            onAction={onAdd}
          />
        )
      }
    />
  );
}
