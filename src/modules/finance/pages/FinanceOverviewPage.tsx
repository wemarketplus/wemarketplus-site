// Read-only Finance overview. Composes the existing financeApi (invoices +
// payment tracking) into a small summary dashboard: headline stat tiles derived
// from the current invoices page plus a recent-invoices table. Deliberately
// read-only — full invoice CRUD lives in the invoices module.
import { Card, CardContent } from '@/shared/ui/core';
import { DataTable, Pill, StatTile, type Column, type PillProps } from '@/shared/ui/data-display';
import { extractApiErrorMessage } from '@/shared/utils/errorUtils';
import { formatDate } from '@/shared/utils/dateFormatter';
import { useListInvoicesQuery } from '../api/financeApi';
import type { InvoiceStatus } from '../constants/financeConstants';
import type { InvoiceRecord } from '../types/financeTypes';

const MONEY = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  maximumFractionDigits: 0,
});
const money = (v: number) => MONEY.format(v);

const STATUS_TONE: Record<InvoiceStatus, PillProps['tone']> = {
  draft: 'b',
  sent: 'y',
  paid: 'g',
  overdue: 'r',
  cancelled: 'r',
};

export function FinanceOverviewPage() {
  // Pull a generous first page to summarise; the overview is a snapshot, not a
  // paginated browser (that is the invoices module's job).
  const { data, isLoading, error } = useListInvoicesQuery({ page: 1, limit: 100 });

  const invoices: InvoiceRecord[] = data?.data ?? [];
  const total = data?.total ?? invoices.length;

  const sum = (pred: (i: InvoiceRecord) => boolean) =>
    invoices.filter(pred).reduce((acc, i) => acc + (i.amount ?? 0), 0);

  const outstanding = sum((i) => i.status === 'sent' || i.status === 'overdue');
  const paid = sum((i) => i.status === 'paid');
  const overdueCount = invoices.filter((i) => i.status === 'overdue').length;

  const recent = [...invoices]
    .sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1))
    .slice(0, 8);

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
    { key: 'amount', header: 'Amount', cell: (i) => money(i.amount ?? 0) },
    {
      key: 'status',
      header: 'Status',
      cell: (i) => <Pill tone={STATUS_TONE[i.status]}>{i.status}</Pill>,
    },
    { key: 'due', header: 'Due', cell: (i) => (i.dueDate ? formatDate(i.dueDate) : '—') },
  ];

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-1">
        <h1 className="font-display text-3xl text-foreground">Finance overview</h1>
        <p className="text-sm text-muted">Invoice and revenue snapshot across your tenant</p>
      </header>

      {error ? (
        <p className="rounded-md border border-destructive/40 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive">
          {extractApiErrorMessage(error, 'Failed to load finance data')}
        </p>
      ) : null}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile label="Invoices" value={String(total)} tone="b" />
        <StatTile label="Outstanding" value={money(outstanding)} tone="y" hint="Sent + overdue" />
        <StatTile label="Collected" value={money(paid)} tone="g" hint="Paid invoices" />
        <StatTile
          label="Overdue"
          value={String(overdueCount)}
          tone="r"
          hint={overdueCount === 1 ? 'invoice' : 'invoices'}
        />
      </div>

      <Card>
        <CardContent className="space-y-4 pt-6">
          <h2 className="text-sm font-semibold uppercase tracking-[0.08em] text-muted">
            Recent invoices
          </h2>
          {isLoading ? (
            <div className="rounded-[12px] border border-white/[0.09] bg-surface p-10 text-center text-[13px] text-muted">
              Loading…
            </div>
          ) : (
            <DataTable
              columns={columns}
              rows={recent}
              rowKey={(i) => i.id}
              empty="No invoices yet."
            />
          )}
        </CardContent>
      </Card>
    </div>
  );
}
