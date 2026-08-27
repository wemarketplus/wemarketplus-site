import { Wrench } from 'lucide-react';
import { CL_MANAGEMENT_ROLES, useRole } from '@/shared/rbac';
import { DataTable, Pill, StatusSelect, type Column } from '@/shared/ui/data-display';
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
  /** Resolves an assignee id to a name — see useOpsStaff. */
  assigneeName: (id: string | null) => string;
  isMutating: boolean;
  hasFilters: boolean;
  onEdit?: (t: ClMaintenanceTicketRecord) => void;
  onDelete?: (t: ClMaintenanceTicketRecord) => void;
  onStatusChange?: (t: ClMaintenanceTicketRecord, status: string) => void;
  onAdd?: () => void;
  // Maintenance View (Housekeeping, Max tier): a plain read-only render of the
  // same data — no status editing, no row actions, no add.
  readOnly?: boolean;
}

export function MaintenanceTable({
  tickets,
  assigneeName,
  isMutating,
  hasFilters,
  onEdit,
  onDelete,
  onStatusChange,
  onAdd,
  readOnly = false,
}: MaintenanceTableProps) {
  const { isAny } = useRole();
  const canDelete = isAny(CL_MANAGEMENT_ROLES);

  const columns: ReadonlyArray<Column<ClMaintenanceTicketRecord>> = [
    {
      key: 'ticket',
      header: 'Ticket',
      cell: (t) => <span className="font-bold text-foreground">{t.ticketNumber ?? '—'}</span>,
    },
    /**
     * The Issue cell says the ISSUE. Nothing else.
     *
     * It used to carry the reporter's name on a second line under it, which is
     * the "Reporter Name is incorrectly displayed in the Issue tab" report: a
     * name stacked under an issue reads as part of the issue, and the column
     * header promises one thing while the cell shows two.
     *
     * The name is not lost and no column is added for it — this table is already
     * six columns wide and who reported a ticket is not what a dispatcher scans
     * the board for. It stays collected and editable on the ticket itself
     * (`reporterName` in MAINTENANCE_FIELDS, "Reported by"), which is where it is
     * legitimately required, and it is still searched server-side.
     */
    {
      key: 'issue',
      header: 'Issue',
      cell: (t) => <span className="text-foreground">{t.issue}</span>,
    },
    {
      key: 'priority',
      header: 'Priority',
      cell: (t) => (
        <Pill tone={TICKET_PRIORITY_PILL[t.priority]}>{TICKET_PRIORITY_LABELS[t.priority]}</Pill>
      ),
    },
    {
      key: 'assignee',
      header: 'Assigned to',
      cell: (t) => assigneeName(t.assignedTo),
    },
    {
      key: 'status',
      header: 'Status',
      cell: (t) =>
        readOnly || !onStatusChange ? (
          <Pill tone={MAINTENANCE_STATUS_PILL[t.status]}>
            {MAINTENANCE_STATUS_LABELS[t.status]}
          </Pill>
        ) : (
          // Editable: ONE control that is both the badge and the picker, so the
          // status is not stated twice. The read-only branch above stays a plain
          // Pill — same shape and tone, minus the affordance.
          <StatusSelect
            value={t.status}
            tone={MAINTENANCE_STATUS_PILL[t.status]}
            options={MAINTENANCE_STATUS_OPTIONS}
            disabled={isMutating}
            onChange={(status) => onStatusChange(t, status)}
            aria-label="Change status"
          />
        ),
    },
    ...(readOnly
      ? []
      : [
          {
            key: 'actions',
            header: '',
            headerClassName: 'w-20',
            className: 'text-right',
            cell: (t: ClMaintenanceTicketRecord) => (
              <EntityRowActions
                onEdit={onEdit ? () => onEdit(t) : undefined}
                onDelete={canDelete && onDelete ? () => onDelete(t) : undefined}
                disabled={isMutating}
                editLabel="Edit ticket"
                deleteLabel="Delete ticket"
              />
            ),
          },
        ]),
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
