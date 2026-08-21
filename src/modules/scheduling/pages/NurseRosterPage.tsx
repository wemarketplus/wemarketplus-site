import { useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Button, DatePicker, Input, Label, Select } from '@/shared/ui/core';
import { Alert, DataTable, Pill, type Column } from '@/shared/ui/data-display';
import { useListUsersQuery } from '@/modules/users';
import {
  useCreateShiftMutation,
  useGetCoverageQuery,
  useListShiftsQuery,
} from '../api/schedulingApi';
import {
  SHIFT_TYPE_LABELS,
  type CoverageDay,
  type NurseShiftRecord,
  type NurseShiftType,
} from '../types/schedulingTypes';

/** Local calendar day as YYYY-MM-DD — a roster day, not an instant. */
function localDate(offsetDays = 0): string {
  const d = new Date(Date.now() + offsetDays * 86_400_000);
  const m = String(d.getMonth() + 1).padStart(2, '0');
  const day = String(d.getDate()).padStart(2, '0');
  return `${d.getFullYear()}-${m}-${day}`;
}

const hours = (minutes: number) => `${(minutes / 60).toFixed(1)}h`;

/**
 * The Nurse Scheduling Engine — what the Gold "Smart scheduling" screen becomes.
 *
 * Two things on one page: the roster itself, and the coverage strip that answers the
 * only question a scheduler urgently has — which days have visits booked with nobody
 * rostered against them. An uncovered visit is called out in red rather than left for
 * the reader to spot by comparing two numbers.
 */
export function NurseRosterPage() {
  const [from, setFrom] = useState(localDate());
  const [to, setTo] = useState(localDate(13));

  const { data: coverage, isLoading: loadingCoverage } = useGetCoverageQuery({
    from,
    to,
  });
  const { data: shifts, isLoading: loadingShifts } = useListShiftsQuery({
    from,
    to,
    limit: 100,
  });
  const { data: users } = useListUsersQuery({ limit: 100 });
  const [create, { isLoading: isSaving }] = useCreateShiftMutation();

  const [nurseId, setNurseId] = useState('');
  const [date, setDate] = useState(localDate());
  const [startTime, setStartTime] = useState('09:00');
  const [endTime, setEndTime] = useState('12:00');
  const [shiftType, setShiftType] = useState<NurseShiftType>('visit');

  // Nurses first, but not nurses only: on a small agency a manager covers visits too,
  // and refusing to roster them would make the screen unusable rather than correct.
  const staff = useMemo(() => users?.data ?? [], [users]);
  const nurseName = (id: string) => {
    const match = staff.find((u) => u.id === id);
    return match ? `${match.firstName} ${match.lastName}`.trim() : id.slice(0, 8);
  };

  const submit = async () => {
    if (!nurseId) {
      toast.error('Pick who is working.');
      return;
    }
    try {
      await create({ nurseId, date, startTime, endTime, shiftType }).unwrap();
      toast.success('Shift rostered.');
    } catch (error) {
      // 409 is the double-booking guard, and saying so is more useful than "failed".
      const status = (error as { status?: number })?.status;
      toast.error(
        status === 409
          ? 'That nurse is already rostered over those hours.'
          : 'Could not roster that shift.',
      );
    }
  };

  const coverageColumns: ReadonlyArray<Column<CoverageDay>> = [
    {
      key: 'date',
      header: 'Day',
      cell: (row) => <span className="font-bold text-foreground">{row.date}</span>,
    },
    { key: 'nurses', header: 'Rostered', cell: (row) => row.nurses },
    { key: 'visitMinutes', header: 'Visit time', cell: (row) => hours(row.visitMinutes) },
    { key: 'onCallMinutes', header: 'On call', cell: (row) => hours(row.onCallMinutes) },
    { key: 'appointments', header: 'Visits booked', cell: (row) => row.appointments },
    {
      key: 'uncoveredAppointments',
      header: 'Uncovered',
      cell: (row) =>
        row.uncoveredAppointments > 0 ? (
          <Pill tone="r">{row.uncoveredAppointments} uncovered</Pill>
        ) : (
          <Pill tone="g">Covered</Pill>
        ),
    },
  ];

  const shiftColumns: ReadonlyArray<Column<NurseShiftRecord>> = [
    { key: 'date', header: 'Day', cell: (row) => row.date },
    {
      key: 'nurseId',
      header: 'Nurse',
      cell: (row) => (
        <span className="font-bold text-foreground">{nurseName(row.nurseId)}</span>
      ),
    },
    {
      key: 'time',
      header: 'Hours',
      cell: (row) => `${row.startTime.slice(0, 5)}–${row.endTime.slice(0, 5)}`,
    },
    {
      key: 'shiftType',
      header: 'Type',
      cell: (row) => SHIFT_TYPE_LABELS[row.shiftType] ?? row.shiftType,
    },
    { key: 'status', header: 'Status', cell: (row) => row.status },
    {
      key: 'appointmentId',
      header: 'Covers a visit',
      cell: (row) => (row.appointmentId ? 'Yes' : '—'),
    },
  ];

  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">Nurse scheduling</h1>
        <p className="text-sm text-muted">
          Roster nurses and see where booked visits have nobody assigned.
        </p>
      </header>

      {coverage && coverage.totalUncovered > 0 && (
        <Alert tone="r">
          <strong className="font-bold">
            {coverage.totalUncovered} visit
            {coverage.totalUncovered === 1 ? '' : 's'} with no nurse rostered.
          </strong>{' '}
          Those appointments are on the calendar but are nobody&apos;s job yet.
        </Alert>
      )}

      <div className="flex flex-wrap items-end gap-3">
        <div>
          <Label htmlFor="roster-from">From</Label>
          <DatePicker
            id="roster-from"
            value={from}
            onChange={(e) => setFrom(e.target.value)}
          />
        </div>
        <div>
          <Label htmlFor="roster-to">To</Label>
          <DatePicker
            id="roster-to"
            value={to}
            onChange={(e) => setTo(e.target.value)}
          />
        </div>
      </div>

      {loadingCoverage ? (
        <p className="text-sm text-muted">Loading coverage…</p>
      ) : (
        <DataTable
          columns={coverageColumns}
          rows={coverage?.days ?? []}
          rowKey={(row) => row.date}
        />
      )}

      <section className="space-y-3">
        <h2 className="text-[22px] font-black leading-tight text-foreground">
          Roster a shift
        </h2>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <div>
            <Label htmlFor="roster-nurse">Who</Label>
            <Select
              id="roster-nurse"
              value={nurseId}
              onChange={(e) => setNurseId(e.target.value)}
            >
              <option value="">Select…</option>
              {staff.map((u) => (
                <option key={u.id} value={u.id}>
                  {`${u.firstName} ${u.lastName}`.trim()} · {u.role}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <Label htmlFor="roster-date">Day</Label>
            <DatePicker
              id="roster-date"
              value={date}
              onChange={(e) => setDate(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="roster-start">Start</Label>
            <Input
              id="roster-start"
              type="time"
              value={startTime}
              onChange={(e) => setStartTime(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="roster-end">End</Label>
            <Input
              id="roster-end"
              type="time"
              value={endTime}
              onChange={(e) => setEndTime(e.target.value)}
            />
          </div>
          <div>
            <Label htmlFor="roster-type">Type</Label>
            <Select
              id="roster-type"
              value={shiftType}
              onChange={(e) => setShiftType(e.target.value as NurseShiftType)}
            >
              {(Object.keys(SHIFT_TYPE_LABELS) as NurseShiftType[]).map((t) => (
                <option key={t} value={t}>
                  {SHIFT_TYPE_LABELS[t]}
                </option>
              ))}
            </Select>
          </div>
        </div>
        <Button onClick={() => void submit()} disabled={isSaving}>
          {isSaving ? 'Rostering…' : 'Roster shift'}
        </Button>
      </section>

      {loadingShifts ? (
        <p className="text-sm text-muted">Loading roster…</p>
      ) : (
        <DataTable
          columns={shiftColumns}
          rows={shifts?.data ?? []}
          rowKey={(row) => row.id}
        />
      )}
    </div>
  );
}
