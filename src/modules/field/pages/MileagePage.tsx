import { useState } from 'react';
import { toast } from 'sonner';
import { Button, Input, Label } from '@/shared/ui/core';
import { Alert, DataTable, type Column } from '@/shared/ui/data-display';
import {
  useCreateMileageLogMutation,
  useListMileageLogsQuery,
} from '../api/mileageApi';
import type { MileageLogRecord } from '../types/fieldTypes';

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

  const logs = data?.data ?? [];
  const totalMiles = logs.reduce((sum, log) => sum + Number(log.miles ?? 0), 0);
  const totalReimbursement = logs.reduce(
    (sum, log) => sum + Number(log.reimbursementAmount ?? 0),
    0,
  );

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
  ];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">
          Mileage &amp; expenses
        </h1>
        <p className="text-sm text-muted">
          {totalMiles.toFixed(1)} miles logged ·{' '}
          {money(totalReimbursement)} reimbursable
        </p>
      </header>

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
    </div>
  );
}
