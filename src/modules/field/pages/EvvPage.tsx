import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useState } from 'react';
import { toast } from 'sonner';
import {
  useClockInMutation,
  useClockOutMutation,
  useListEvvLogsQuery,
} from '@/modules/clinical';
import {
  EMPTY_LOCATION,
  LocationField,
  fromLocationValue,
  type LocationValue,
} from '@/modules/geocoding';
import { Button, Input, Label } from '@/shared/ui/core';
import { Alert, DataTable, type Column } from '@/shared/ui/data-display';
import type { EvvLogRecord } from '@/modules/clinical/types/clinicalApiTypes';

/**
 * Electronic Visit Verification — clock in at a visit, clock out when it ends.
 *
 * The `evv_logs` table, the `/evv-logs` endpoints (including `clock-in` and
 * `clock-out`) and the RTK hooks below have all existed for some time with **zero
 * components consuming them**: no nav entry, no route. EVV was therefore "API only"
 * while being sold at Max, and it was the one item where the sales demo showed a
 * finished screen the product did not have. This is that screen.
 *
 * The open visit is derived from the data (a row with a clock-in and no clock-out)
 * rather than tracked in local state, so a rep who clocks in on a phone and returns
 * on a laptop still sees the visit as open.
 */
export function EvvPage() {
  // No userId is passed deliberately. EvvController pins a non-oversight caller to
  // their own id and ignores any userId in the query, so scoping lives in exactly
  // one place — a second copy of the rule here could only ever drift from it.
  const { data, isLoading, isError } = useListEvvLogsQuery({ limit: 50 });
  const [clockIn, { isLoading: isClockingIn }] = useClockInMutation();
  const [clockOut, { isLoading: isClockingOut }] = useClockOutMutation();

  const [visitType, setVisitType] = useState('');
  // A place, not a string. EVV is sold as "EVV/GPS ... compliance log", and a
  // verification record whose location is only whatever the worker typed is the
  // part that was missing: the same four characters can be typed from anywhere.
  const [location, setLocation] = useState<LocationValue>(EMPTY_LOCATION);
  const [notes, setNotes] = useState('');

  const logs = data?.data ?? [];
  const openVisit = logs.find((log) => log.clockIn && !log.clockOut) ?? null;

  const onClockIn = async () => {
    try {
      const { label, lat, lng } = fromLocationValue(location);
      await clockIn({
        visitType: visitType || undefined,
        locationIn: label,
        // Paired or absent — the server rejects a lone half.
        locationInLat: lat,
        locationInLng: lng,
        notes: notes || undefined,
      }).unwrap();
      setVisitType('');
      setLocation(EMPTY_LOCATION);
      setNotes('');
      toast.success('Clocked in.');
    } catch {
      toast.error('Could not clock in.');
    }
  };

  const onClockOut = async () => {
    if (!openVisit) return;
    const { label, lat, lng } = fromLocationValue(location);
    try {
      await clockOut({
        id: openVisit.id,
        // `notesOut`, NOT `notes`: this used to send `notes`, which the backend
        // spread over the row and erased whatever was written at clock-in.
        body: {
          locationOut: label,
          // The DEPARTURE fix, written to its own columns. Clock-out cannot
          // reach the clock-in pair, for the same reason it writes `notesOut`
          // rather than `notes`: closing a visit must not rewrite what arriving
          // at it recorded.
          locationOutLat: lat,
          locationOutLng: lng,
          notesOut: notes || undefined,
        },
      }).unwrap();
      setLocation(EMPTY_LOCATION);
      setNotes('');
      toast.success('Clocked out.');
    } catch {
      toast.error('Could not clock out.');
    }
  };

  const columns: ReadonlyArray<Column<EvvLogRecord>> = [
    {
      key: 'visitType',
      header: 'Visit',
      cell: (row) => (
        <span className="font-bold text-foreground">
          {row.visitType ?? 'Visit'}
        </span>
      ),
    },
    {
      key: 'clockIn',
      header: 'Clocked in',
      cell: (row) => (row.clockIn ? new Date(row.clockIn).toLocaleString() : '—'),
    },
    {
      key: 'clockOut',
      header: 'Clocked out',
      // An open visit is stated as such rather than shown as a blank cell.
      cell: (row) =>
        row.clockOut ? (
          new Date(row.clockOut).toLocaleString()
        ) : (
          <span className="text-warning">In progress</span>
        ),
    },
    {
      key: 'locationIn',
      header: 'Location',
      // Both ends, because they can differ (picked up at the office, dropped at a
      // facility) and a compliance record that shows only one is misleading.
      cell: (row) =>
        row.locationOut && row.locationOut !== row.locationIn ? (
          <span>
            {row.locationIn ?? '—'}
            <span className="text-muted-soft"> → </span>
            {row.locationOut}
          </span>
        ) : (
          (row.locationIn ?? row.locationOut ?? '—')
        ),
    },
    {
      key: 'notes',
      header: 'Notes',
      // Arrival and departure notes are shown as distinct, labelled lines. They
      // used to share one column AND one database field, so writing the second
      // destroyed the first.
      cell: (row) =>
        row.notes || row.notesOut ? (
          <span className="block space-y-0.5">
            {row.notes && (
              <span className="block">
                <span className="text-[11px] uppercase tracking-wide text-muted-soft">
                  In{' '}
                </span>
                {row.notes}
              </span>
            )}
            {row.notesOut && (
              <span className="block">
                <span className="text-[11px] uppercase tracking-wide text-muted-soft">
                  Out{' '}
                </span>
                {row.notesOut}
              </span>
            )}
          </span>
        ) : (
          '—'
        ),
    },
  ];

  return (
    <div className="space-y-6">
      <header>
        <h1 className={PAGE_TITLE}>
          Visit verification
        </h1>
        <p className="text-sm text-muted">
          Clock in and out of visits. Each entry is a timestamped compliance record.
        </p>
      </header>

      {isError && (
        <Alert tone="r">
          <strong className="font-bold">Visit log unavailable.</strong> The
          /evv-logs endpoint did not answer. Visit verification is a Max-tier
          feature — check your plan if this persists.
        </Alert>
      )}

      {openVisit && (
        <Alert tone="y">
          <strong className="font-bold">A visit is open.</strong> Started{' '}
          {openVisit.clockIn
            ? new Date(openVisit.clockIn).toLocaleString()
            : 'earlier'}
          . Clock out to close the record.
        </Alert>
      )}

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        {!openVisit && (
          <div>
            <Label htmlFor="evv-visit-type">Visit type</Label>
            <Input
              id="evv-visit-type"
              value={visitType}
              onChange={(e) => setVisitType(e.target.value)}
              placeholder="Assessment, routine, bereavement…"
            />
          </div>
        )}
        <LocationField
          id="evv-location"
          label="Location"
          value={location}
          onChange={setLocation}
          placeholder="Address or facility"
        />
        <div>
          <Label htmlFor="evv-notes">Notes</Label>
          <Input
            id="evv-notes"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Optional"
          />
        </div>
      </div>

      <div className="flex gap-2">
        {openVisit ? (
          <Button onClick={onClockOut} disabled={isClockingOut}>
            {isClockingOut ? 'Clocking out…' : 'Clock out'}
          </Button>
        ) : (
          <Button onClick={onClockIn} disabled={isClockingIn}>
            {isClockingIn ? 'Clocking in…' : 'Clock in'}
          </Button>
        )}
      </div>

      {isLoading ? (
        <p className="text-sm text-muted">Loading visits…</p>
      ) : (
        <DataTable columns={columns} rows={logs} rowKey={(row) => row.id} />
      )}
    </div>
  );
}
