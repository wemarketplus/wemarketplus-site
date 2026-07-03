import { DataTable, Pill, type Column, type PillProps } from '@/shared/ui/data-display';
import { EntityRowActions } from '@/shared/ui/entity';
import { formatDate } from '@/shared/utils/dateFormatter';
import { formatMoney } from '../utils/invoicesUtils';
import type { InvoiceStatus } from '../constants/invoicesConstants';
import type { InvoiceRecord } from '../types/invoicesTypes';

interface InvoicesTableProps {
  invoices: readonly InvoiceRecord[];
  isMutating: boolean;
  onEdit: (invoice: InvoiceRecord) => void;
}

const STATUS_TONE: Record<InvoiceStatus, PillProps['tone']> = {
  draft: 'b',
  sent: 'y',
  paid: 'g',
  overdue: 'r',
  cancelled: 'r',
};

export function InvoicesTable({ invoices, isMutating, onEdit }: InvoicesTableProps) {
  const columns: ReadonlyArray<Column<InvoiceRecord>> = [
    {
      key: 'invoice',
      header: 'Invoice',
      cell: (i) => (
        <div>
          <p className="font-bold text-[#111]">{i.companyName}</p>
          <p className="text-[11px] text-[#667]">{i.invoiceNumber}</p>
        </div>
      ),
    },
    { key: 'amount', header: 'Amount', cell: (i) => formatMoney(i.amount) },
    {
      key: 'status',
      header: 'Status',
      cell: (i) => <Pill tone={STATUS_TONE[i.status]}>{i.status}</Pill>,
    },
    { key: 'due', header: 'Due', cell: (i) => (i.dueDate ? formatDate(i.dueDate) : '—') },
    { key: 'created', header: 'Created', cell: (i) => formatDate(i.createdAt) },
    {
      key: 'actions',
      header: '',
      headerClassName: 'w-20',
      className: 'text-right',
      cell: (i) => (
        // Invoices have no DELETE endpoint — edit only.
        <EntityRowActions
          onEdit={() => onEdit(i)}
          disabled={isMutating}
          editLabel={`Edit ${i.invoiceNumber}`}
        />
      ),
    },
  ];

  return (
    <DataTable
      columns={columns}
      rows={invoices}
      rowKey={(i) => i.id}
      empty="No invoices match the current filters."
    />
  );
}
