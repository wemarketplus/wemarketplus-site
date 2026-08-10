import { useState } from 'react';
import { CalendarDays, List, Plus } from 'lucide-react';
import { useListJobsQuery } from '@/modules/jobs';
import { Button } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { AppointmentsCalendar } from '../components/AppointmentsCalendar';
import { CalendarScopeToggle } from '../components/CalendarScopeToggle';
import { AppointmentsDayPanel } from '../components/AppointmentsDayPanel';
import { AppointmentsMonthGrid } from '../components/AppointmentsMonthGrid';
import { CompleteAppointmentModal } from '../components/CompleteAppointmentModal';
import { ScheduleAppointmentModal } from '../components/ScheduleAppointmentModal';
import { useAppointmentActions } from '../hooks/useAppointmentActions';
import { useAppointmentsCalendar } from '../hooks/useAppointmentsCalendar';
import { useAppointmentsMonth } from '../hooks/useAppointmentsMonth';
import { useTenantCalendarColors } from '../hooks/useTenantCalendarColors';

type CalendarMode = 'month' | 'agenda';

/**
 * The real appointment calendar, backed by hl_appointments.
 *
 * Two views over the same feed: a month grid (where am I this month) and the
 * chronological agenda (what's next). The month view fetches the whole visible
 * grid; the agenda fetches the next 60 days.
 */
export function AppointmentsPage() {
  const [mode, setMode] = useState<CalendarMode>('month');
  const month = useAppointmentsMonth();
  const agenda = useAppointmentsCalendar();
  const {
    pending,
    openComplete,
    closeComplete,
    isCompleting,
    submitComplete,
    scheduleOpen,
    openSchedule,
    closeSchedule,
    isScheduling,
    submitSchedule,
  } = useAppointmentActions();
  // An appointment always hangs off a job, so the picker needs the job list.
  const { data: jobsPage } = useListJobsQuery({ limit: 100 });
  // Per-rep colours, only for the "All users" agenda. Saving a colour in
  // /my-profile invalidates this query's tag, so the dots repaint here without
  // a reload — including for whoever else is looking at the same view.
  const ownerColorMap = useTenantCalendarColors(
    mode === 'agenda' && agenda.scope === 'all',
  );

  const isMonth = mode === 'month';
  const active = isMonth ? month : agenda;

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Appointments</h1>
          <p className="text-sm text-muted">
            {isMonth
              ? `${month.appointments.length} in view`
              : `${agenda.appointments.length} scheduled in the next 60 days`}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {/* View switch — same data, two shapes. */}
          <div className="flex items-center rounded-pill border border-border p-0.5">
            {(
              [
                ['month', 'Month', CalendarDays],
                ['agenda', 'Agenda', List],
              ] as const
            ).map(([value, label, Icon]) => (
              <button
                key={value}
                type="button"
                onClick={() => setMode(value)}
                className={cn(
                  'flex items-center gap-1.5 rounded-pill px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.08em] transition',
                  mode === value
                    ? 'bg-primary/15 text-primary'
                    : 'text-muted hover:text-foreground',
                )}
              >
                <Icon className="h-3.5 w-3.5" />
                {label}
              </button>
            ))}
          </div>
          <Button onClick={openSchedule}>
            <Plus className="h-4 w-4" /> Schedule appointment
          </Button>
        </div>
      </header>

      {active.isError && (
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          Could not load the calendar.
        </p>
      )}

      {active.isLoading ? (
        <p className="text-sm text-muted-soft">Loading calendar…</p>
      ) : isMonth ? (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_300px]">
          <AppointmentsMonthGrid
            month={month.month}
            cells={month.cells}
            selectedKey={month.selectedKey}
            onPrevMonth={month.prevMonth}
            onNextMonth={month.nextMonth}
            onToday={month.goToday}
            isFetching={month.isFetching}
            onSelectDay={month.selectDay}
            onOpenAppointment={openComplete}
          />
          <AppointmentsDayPanel
            dateKey={month.selectedKey}
            items={month.selectedDay?.items ?? []}
            isBusy={isCompleting}
            onComplete={openComplete}
            onSchedule={openSchedule}
          />
        </div>
      ) : (
        <div className="space-y-3">
          <CalendarScopeToggle scope={agenda.scope} onChange={agenda.setScope} />
          <AppointmentsCalendar
            showOwnerColors={agenda.scope === 'all'}
            ownerColorMap={ownerColorMap}
            days={agenda.days}
            isEmpty={agenda.isEmpty}
            isBusy={isCompleting}
            onComplete={openComplete}
          />
        </div>
      )}

      <ScheduleAppointmentModal
        open={scheduleOpen}
        isSaving={isScheduling}
        jobs={jobsPage?.data ?? []}
        onClose={closeSchedule}
        onSubmit={submitSchedule}
      />
      <CompleteAppointmentModal
        appointment={pending}
        isSaving={isCompleting}
        onClose={closeComplete}
        onSubmit={(id, body) => void submitComplete(id, body)}
      />
    </div>
  );
}
