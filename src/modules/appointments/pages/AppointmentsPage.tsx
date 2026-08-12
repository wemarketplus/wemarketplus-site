import { useState } from 'react';
import { CalendarDays, List, Plus } from 'lucide-react';
import { useListJobsQuery } from '@/modules/jobs';
import { HL_MARKETING_ROLES, useRole } from '@/shared/rbac';
import { Button } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { AppointmentsCalendar } from '../components/AppointmentsCalendar';
import { CalendarScopeToggle } from '../components/CalendarScopeToggle';
import { AppointmentsDayPanel } from '../components/AppointmentsDayPanel';
import { AppointmentsMonthGrid } from '../components/AppointmentsMonthGrid';
import { CompleteAppointmentModal } from '../components/CompleteAppointmentModal';
import { ScheduleAppointmentModal } from '../components/ScheduleAppointmentModal';
import { useAppointmentActions } from '../hooks/useAppointmentActions';
import {
  useAppointmentsCalendar,
  type CalendarScope,
} from '../hooks/useAppointmentsCalendar';
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
  // ONE scope for both views. Previously only the agenda had this control, so the
  // month grid — the view the page opens on — was always tenant-wide, and moving
  // between tabs quietly changed whose calendar you were reading.
  const [scope, setScope] = useState<CalendarScope>('mine');
  // Every appointment hangs off a job, and the create form requires one. Roles
  // without pipeline access get 403 on /hl/jobs and cannot create a job anywhere in
  // their own menu, so for them the create button opened a form whose required Job
  // dropdown held nothing but its placeholder — POST /hl/appointments answers
  // "jobId must be a UUID" no matter what they type. Hidden rather than disabled:
  // a caregiver is not waiting on a permission here, scheduling simply is not part
  // of their job.
  const canSchedule = useRole().isAny(HL_MARKETING_ROLES);
  const month = useAppointmentsMonth(scope);
  // `includeOverdue`: the agenda is where the guide sends a nurse to "see just your
  // own scheduled visits", and a visit still open from before today is the one they
  // most need to see. Without it the month grid showed a visit the agenda swore did
  // not exist.
  const agenda = useAppointmentsCalendar({ scope, includeOverdue: true });
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
  // Skipped for roles without pipeline access: /hl/jobs is 403 for them, and it was
  // firing on every calendar load to populate a form they can never open.
  const { data: jobsPage } = useListJobsQuery(
    { limit: 100 },
    { skip: !canSchedule },
  );
  // Per-rep colours for the calendar. The tenant list is fetched only for "All
  // users"; on "My calendar" the hook supplies the session user's own colour from
  // the auth slice at no network cost, so a user who just picked one sees it on
  // the view the page opens on. Saving a colour in /my-profile invalidates this
  // query's tag, so the blocks repaint without a reload — including for whoever
  // else is looking at the same view.
  const ownerColorMap = useTenantCalendarColors(scope === 'all');

  const isMonth = mode === 'month';
  const active = isMonth ? month : agenda;

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          {/* "Calendar", matching the sidebar row that now leads here. The product
              guide sends every role to a tab by that name for the month grid and
              the My calendar / All users switch, both of which are on this screen
              and nowhere else. */}
          <h1 className="font-display text-3xl text-foreground">Calendar</h1>
          {/* The agenda counts overdue visits SEPARATELY rather than folding them
              into "scheduled in the next 60 days", which would have been a false
              statement about a visit that was due yesterday. */}
          <p className="text-sm text-muted">
            {isMonth
              ? [
                  `${month.appointments.length} visit${month.appointments.length === 1 ? '' : 's'} in view`,
                  month.followUpsInView > 0
                    ? `${month.followUpsInView} follow-up${month.followUpsInView === 1 ? '' : 's'}`
                    : null,
                ]
                  .filter(Boolean)
                  .join(' · ')
              : [
                  agenda.overdueCount > 0
                    ? `${agenda.overdueCount} still open from earlier`
                    : null,
                  `${agenda.appointments.length - agenda.overdueCount} scheduled in the next 60 days`,
                ]
                  .filter(Boolean)
                  .join(' · ')}
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
          {canSchedule && (
            <Button onClick={openSchedule}>
              <Plus className="h-4 w-4" /> Schedule appointment
            </Button>
          )}
        </div>
      </header>

      {active.isError && (
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          Could not load the calendar.
        </p>
      )}

      {/* Above the view switch, so the answer to "whose calendar is this?" is on
          screen in BOTH views rather than only in the agenda. */}
      <CalendarScopeToggle scope={scope} onChange={setScope} />

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
            ownerColorMap={ownerColorMap}
          />
          <AppointmentsDayPanel
            dateKey={month.selectedKey}
            items={month.selectedDay?.items ?? []}
            followUps={month.selectedDay?.followUps ?? []}
            isBusy={isCompleting}
            onComplete={openComplete}
            onSchedule={canSchedule ? openSchedule : undefined}
          />
        </div>
      ) : (
        <div className="space-y-3">
          <AppointmentsCalendar
            showOwnerColors={scope === 'all'}
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
