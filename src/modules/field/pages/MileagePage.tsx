import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Download, MapPin, Paperclip } from 'lucide-react';
import { useCsvDownload } from '@/shared/hooks';
import {
  EMPTY_LOCATION,
  LocationField,
  type LocationValue,
} from '@/modules/geocoding';
import { Button, DatePicker, Input, Label } from '@/shared/ui/core';
import { Alert, DataTable, type Column } from '@/shared/ui/data-display';
import { StatTile } from '@/shared/ui/data-display';
import { mileageLogsToCsv } from '../utils/mileageCsv';
import { AttachReceiptDialog } from '../components/AttachReceiptDialog';
import { ExpenseReceipts } from '../components/ExpenseReceipts';
import { ReceiptFileButton } from '../components/ReceiptFileButton';
import {
  useCreateMileageLogMutation,
  useGetMileageSummaryQuery,
  useListExpenseReceiptsQuery,
  useListMileageLogsQuery,
} from '../api/mileageApi';
import {
  endpointFields,
  hasCoordinates,
  routeCoordinates,
} from '../utils/tripLocations';
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
  // From/To are LOCATIONS now, not strings: a label a reviewer reads plus the
  // coordinates it stands for. `EMPTY_LOCATION` is both halves absent — the same
  // state a trip typed before the picker existed comes back in.
  const [fromLocation, setFrom] = useState<LocationValue>(EMPTY_LOCATION);
  const [toLocation, setTo] = useState<LocationValue>(EMPTY_LOCATION);
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

  /**
   * "Export CSV any time you need your mileage log as a spreadsheet" — the one
   * step of the client's mileage flow that had nothing behind it.
   *
   * Exports the LOADED trips, and the button says so, because that is what this
   * screen holds: `useListMileageLogsQuery({ limit: 50 })` is the most recent
   * page, not the year. Silently exporting 50 rows under a bare "Export CSV" is
   * how someone files an expense claim short — the count in the label is the
   * whole safeguard until the endpoint grows a date range.
   */
  const downloadCsv = useCsvDownload();
  const onExport = () => {
    if (logs.length === 0) {
      toast.error('No trips to export yet.');
      return;
    }
    downloadCsv(mileageLogsToCsv(logs), 'mileage');
  };

  const onSubmit = async () => {
    const parsed = Number(miles);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      toast.error('Enter the miles driven.');
      return;
    }
    try {
      await create({
        date,
        ...endpointFields('from', fromLocation),
        ...endpointFields('to', toLocation),
        purpose: purpose || undefined,
        miles: parsed,
      }).unwrap();
      setFrom(EMPTY_LOCATION);
      setTo(EMPTY_LOCATION);
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
      // The pin marks a trip whose endpoints were PICKED rather than typed, and
      // its tooltip carries the coordinates. Kept to an icon: the route names
      // are what an expense reviewer reads down the column, and two lat/lng
      // pairs per row would bury them.
      cell: (row) => (
        <span className="inline-flex items-center gap-1.5">
          {`${row.fromLocation ?? '—'} → ${row.toLocation ?? '—'}`}
          {hasCoordinates(row) && (
            <span title={routeCoordinates(row)}>
              <MapPin
                className="h-3 w-3 shrink-0 text-primary"
                aria-label="Locations captured on a map"
              />
            </span>
          )}
        </span>
      ),
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
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">
            Mileage &amp; expenses
          </h1>
          <p className="text-sm text-muted">
            Log a trip and the reimbursement is calculated at your tenant's rate.
          </p>
        </div>
        <Button variant="secondary" onClick={onExport} disabled={logs.length === 0}>
          <Download className="h-4 w-4" />
          Export CSV ({logs.length})
        </Button>
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
        <div>
          <Label htmlFor="mileage-date">Date</Label>
          <DatePicker
            id="mileage-date"
            value={date}
            onChange={(e) => setDate(e.target.value)}
          />
        </div>
        {/* From/To open the map picker. Same grid cell, same Input styling and
            the same optional-field rules as before — what changed is that the
            value now carries coordinates as well as a name. */}
        <LocationField
          id="mileage-from"
          label="From"
          value={fromLocation}
          onChange={setFrom}
          placeholder="Office"
        />
        <LocationField
          id="mileage-to"
          label="To"
          value={toLocation}
          onChange={setTo}
          placeholder="Mercy General"
        />
        <div>
          <Label htmlFor="mileage-purpose">Purpose</Label>
          <Input
            id="mileage-purpose"
            value={purpose}
            onChange={(e) => setPurpose(e.target.value)}
            placeholder="Assessment visit"
          />
        </div>
        <div>
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
