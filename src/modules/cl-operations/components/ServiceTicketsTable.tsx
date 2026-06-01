import { DataTable, Pill, type Column, type PillProps } from '@/shared/ui/data-display';
import { TicketPriority, type ServiceTicket } from '@/shared/types';
import { TICKET_STATUS_LABEL } from '../constants/clOperationsConstants';

const PRIORITY_PILL: Record<TicketPriority, PillProps['tone']> = {
  [TicketPriority.Urgent]: 'r',
  [TicketPriority.High]: 'y',
  [TicketPriority.Medium]: 'b',
  [TicketPriority.Low]: 'b',
};

const columns: ReadonlyArray<Column<ServiceTicket>> = [
  {
    key: 'unit',
    header: 'Unit',
    cell: (t) => <span className="font-bold text-[#111]">{t.unitNumber}</span>,
  },
  { key: 'title', header: 'Title', cell: (t) => t.title },
  {
    key: 'priority',
    header: 'Priority',
    cell: (t) => <Pill tone={PRIORITY_PILL[t.priority]}>{t.priority}</Pill>,
  },
  { key: 'status', header: 'Status', cell: (t) => TICKET_STATUS_LABEL[t.status] },
  { key: 'assigned', header: 'Assigned', cell: (t) => t.assignedTo },
];

export function ServiceTicketsTable({ tickets }: { tickets: readonly ServiceTicket[] }) {
  return (
    <DataTable
      columns={columns}
      rows={tickets}
      rowKey={(t) => t.id}
      empty="Nothing in the queue."
    />
  );
}
