import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Paperclip } from 'lucide-react';
import { Button, Input, Label } from '@/shared/ui/core';
import { Alert, DataTable, type Column } from '@/shared/ui/data-display';
import { StatTile } from '@/shared/ui/data-display';
import { AttachReceiptDialog } from '../components/AttachReceiptDialog';
import { ExpenseReceipts } from '../components/ExpenseReceipts';
import { ReceiptFileButton } from '../components/ReceiptFileButton';
import {
  useCreateMileageLogMutation,
  useGetMileageSummaryQuery,
  useListExpenseReceiptsQuery,
  useListMileageLogsQuery,
} from '../api/mileageApi';
import type {
  ExpenseReceiptRecord,
  MileageLogRecord,
} from '../types/fieldTypes';

/** Today as YYYY-MM-DD in LOCAL time — a mileage log is a calendar day, not an
 *  instant, so `toISOString()` would file an evening trip under tomorrow. */
function todayLocal(): string {
  const now = new Date();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${now.getFullYear()}-${month}-${day}`;
}

const money = (value: number | null) =>
  value === null
    ? '—'
    : value.toLocaleString('en-US', { style: 'currency', currency: 'USD' });

/**
 * Mileage and expense capture. The `mileage_logs` table and `/mileage-logs`
 * endpoints have existed with no client at all — this is the first UI for them.
 * Sold at Max alongside EVV as "EVV/GPS mileage & compliance log".
 *
 * The reimbursement amount is computed and returned by the server, so it is
 * displayed, never recalculated here: two rounding rules would eventually disagree
 * and the expense report is the record that matters.
 */
export function MileagePage() {
  const { data, isLoading, isError } = useListMileageLogsQuery({ limit: 50 });
  const [create, { isLoading: isSaving }] = useCreateMileageLogMutation();

  const [date, setDate] = useState(todayLocal());
  const [fromLocation, setFrom] = useState('');
  const [toLocation, setTo] = useState('');
  const [purpose, setPurpose] = useState('');
  const [miles, setMiles] = useState('');
  // The trip the attach dialog is filing against. Null = closed.
  const [attachTo, setAttachTo] = useState<MileageLogRecord | null>(null);

  const logs = data?.data ?? [];

  // Receipts are fetched here so the trip table can show what is already
  // attached to each row. Same query args as the panel below, so RTK Query
  // serves both from ONE cache entry and one request — change the args here and
  // the page starts making two.
  const { data: receiptPage } = useListExpenseReceiptsQuery({ limit: 50 });
  const receiptsByTrip = useMemo(() => {
    const grouped = new Map<string, ExpenseReceiptRecord[]>();
    (receiptPage?.data ?? []).forEach((receipt) => {
      if (!receipt.mileageLogId) return;
      const existing = grouped.get(receipt.mileageLogId);
      if (existing) existing.push(receipt);
      else grouped.set(receipt.mileageLogId, [receipt]);
    });
    return grouped;
  }, [receiptPage]);
  // Totals come from the SERVER, not from `logs`: the list is the most recent
  // page, so summing it would under-report a rep who drives a lot — and an
  // expense figure that is quietly too low is worse than showing none.
  const { data: summary } = useGetMileageSummaryQuery();

  const onSubmit = async () => {
    const parsed = Number(miles);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      toast.error('Enter the miles driven.');
      return;
    }
    try {
      await create({
        date,
        fromLocation: fromLocation || undefined,
        toLocation: toLocation || undefined,
        purpose: purpose || undefined,
        miles: parsed,
      }).unwrap();
      setFrom('');
      setTo('');
      setPurpose('');
      setMiles('');
      toast.success('Trip logged.');
    } catch {
      toast.error('Could not log that trip.');
    }
  };

  const columns: ReadonlyArray<Column<MileageLogRecord>> = [
    {
      key: 'date',
      header: 'Date',
      cell: (row) => <span className="font-bold text-foreground">{row.date}</span>,
    },
    {
      key: 'route',
      header: 'Route',
      cell: (row) => `${row.fromLocation ?? '—'} → ${row.toLocation ?? '—'}`,
    },
    { key: 'purpose', header: 'Purpose', cell: (row) => row.purpose ?? '—' },
    { key: 'miles', header: 'Miles', cell: (row) => Number(row.miles).toFixed(1) },
    {
      key: 'reimbursementRate',
      header: 'Rate',
      cell: (row) => money(Number(row.reimbursementRate)),
    },
    {
      key: 'reimbursementAmount',
      header: 'Reimbursement',
      cell: (row) =>
        money(
          row.reimbursementAmount === null
            ? null
            : Number(row.reimbursementAmount),
        ),
    },
    // Receipts live ON THE TRIP ROW, not only in the panel below. A field
    // worker photographs the gas/toll receipt while standing at the pump; being
    // sent to a separate form that then asks them to re-key the date and pick
    // the trip out of a list is how receipts stop getting filed at all.
    {
      key: 'receipts',
      header: 'Receipts',
      cell: (row) => {
        const attached = receiptsByTrip.get(row.id) ?? [];
        return (
          <div className="flex flex-wrap items-center gap-2">
            {attached.map((receipt) => (
              <ReceiptFileButton key={receipt.id} receipt={receipt} compact />
            ))}
            {/* Count link-only receipts too: they are proof as well, just held
                elsewhere, and hiding them would read as "nothing attached". */}
            {attached.some((receipt) => !receipt.hasFile && receipt.receiptUrl) && (
              <span className="text-[11px] text-muted-soft">+ link</span>
            )}
            <button
              type="button"
              onClick={() => setAttachTo(row)}
              className="inline-flex items-center gap-1 text-[11px] font-semibold text-muted hover:text-foreground"
            >
              <Paperclip className="h-3 w-3" />
              {attached.length > 0 ? 'Add' : 'Attach'}
            </button>
          </div>
        );
      },
    },
  ];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">
          Mileage &amp; expenses
        </h1>
        <p className="text-sm text-muted">
          Log a trip and the reimbursement is calculated at your tenant's rate.
        </p>
      </header>

      {/* Week and month to date — the two figures an expense claim is filed on.
          Both are server-aggregated over every trip, not the visible page. */}
      {summary && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatTile
            label="Miles this week"
            value={summary.weekToDate.miles.toFixed(1)}
            hint={`${summary.weekToDate.trips} trip${summary.weekToDate.trips === 1 ? '' : 's'}`}
            tone="b"
          />
          <StatTile
            label="Reimbursable this week"
            value={money(summary.weekToDate.reimbursement)}
            tone="g"
          />
          <StatTile
            label="Miles this month"
            value={summary.monthToDate.miles.toFixed(1)}
            hint={`${summary.monthToDate.trips} trip${summary.monthToDate.trips === 1 ? '' : 's'}`}
            tone="b"
          />
          <StatTile
            label="Reimbursable this month"
            value={money(summary.monthToDate.reimbursement)}
            tone="g"
          />
        </div>
      )}

      {isError && (
        <Alert tone="r">
          <strong className="font-bold">Mileage log unavailable.</strong> The
          /mileage-logs endpoint did not answer.
        </Alert>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3 lg:grid-cols-5">
        <div className="space-y-1.5">
          <Label htmlFor="mileage-date">Date</Label>
          <Input
            id="mileage-date"
            type="date"
            value={date}
            onChange={(e) => setDate(e.target.value)}
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="mileage-from">From</Label>
          <Input
            id="mileage-from"
            value={fromLocation}
            onChange={(e) => setFrom(e.target.value)}
            placeholder="Office"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="mileage-to">To</Label>
          <Input
            id="mileage-to"
            value={toLocation}
            onChange={(e) => setTo(e.target.value)}
            placeholder="Mercy General"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="mileage-purpose">Purpose</Label>
          <Input
            id="mileage-purpose"
            value={purpose}
            onChange={(e) => setPurpose(e.target.value)}
            placeholder="Assessment visit"
          />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="mileage-miles">Miles</Label>
          <Input
            id="mileage-miles"
            type="number"
            min="0"
            step="0.1"
            value={miles}
            onChange={(e) => setMiles(e.target.value)}
            placeholder="12.4"
          />
        </div>
      </div>

      <Button onClick={onSubmit} disabled={isSaving}>
        {isSaving ? 'Logging…' : 'Log trip'}
      </Button>

      {isLoading ? (
        <p className="text-sm text-muted">Loading trips…</p>
      ) : (
        <DataTable columns={columns} rows={logs} rowKey={(row) => row.id} />
      )}

      {/* Receipts: /expense-receipts had a full backend and no client at all,
          so "attach receipt images" was unreachable despite being sold at Max.
          The panel stays because it is where receipts NOT tied to a trip live
          (a conference meal, supplies) and where link-based receipts from
          before uploads existed are still reviewed. */}
      <ExpenseReceipts />

      {/* One dialog for the whole table rather than one per row: mounting a
          modal per trip would put N hidden dialogs in the tree for a rep with a
          busy month. */}
      <AttachReceiptDialog
        open={attachTo !== null}
        onClose={() => setAttachTo(null)}
        trip={attachTo}
      />
    </div>
  );
}
