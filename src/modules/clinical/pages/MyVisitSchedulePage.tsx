import { CalendarClock, TriangleAlert } from 'lucide-react';
import {
  AppointmentsCalendar,
  CompleteAppointmentModal,
  useAppointmentActions,
  useAppointmentsCalendar,
} from '@/modules/appointments';

/**
 * "My visit schedule" — the nurse's own visits, and nobody else's.
 *
 * WHAT THE GUIDE PROMISED, and why this is not just the Calendar screen. The nurse
 * guide advertises "a dedicated view of your own visit schedule", and the sidebar
 * carried it as a `comingSoon` row with no route behind it. The shared Calendar
 * (/appointments) does show a nurse their visits, but it is a month grid plus an
 * agenda with a My-calendar / All-users toggle and a Schedule button — a tenant-wide
 * tool that happens to default to "mine". This screen is the promised thing: one
 * chronological list, permanently self-scoped, with no toggle that can widen it and
 * no create action a nurse has no job to hang an appointment off.
 *
 * BUILT BY COMPOSITION, deliberately — no new endpoint, hook or list component. The
 * feed is `useAppointmentsCalendar` with the scope FIXED to 'mine' (which filters
 * server-side on `assignedRep`, so the cap cannot silently drop a nurse's own
 * visits), and the rendering is the same `AppointmentsCalendar` the agenda tab uses.
 * A second implementation of "my visits" would be a second source of truth for the
 * same rows.
 *
 * `includeOverdue`: a visit still open from before today is the single most important
 * row a nurse can be shown, so the window reaches back rather than starting at today.
 *
 * WHAT FILLS THIS SCREEN: an appointment reaches a nurse only when somebody assigns
 * it to them, which until the "Assign to" picker was added to the two scheduling
 * modals was possible through the API alone. An empty list here for a real nurse
 * usually means nothing has been assigned yet, not that the screen is broken.
 */
export function MyVisitSchedulePage() {
  // Scope is passed, not defaulted, which makes the hook CONTROLLED — there is no
  // setter reachable from this page, so nothing can widen it to the whole tenant.
  const { days, isEmpty, isFetching, isError, overdueCount } =
    useAppointmentsCalendar({ scope: 'mine', includeOverdue: true });

  const { pending, openComplete, closeComplete, isCompleting, submitComplete } =
    useAppointmentActions();

  return (
    <div className="space-y-4">
      <header>
        <h1 className="flex items-center gap-2 text-xl font-semibold text-foreground">
          <CalendarClock className="size-5" aria-hidden />
          My visit schedule
        </h1>
        <p className="text-[13px] text-muted">
          Every visit assigned to you, soonest first. Mark one complete when you
          finish it.
        </p>
      </header>

      {overdueCount > 0 && (
        <p className="flex items-center gap-2 rounded-md bg-warning/10 px-3 py-2 text-[13px] text-warning">
          <TriangleAlert className="size-4 shrink-0" aria-hidden />
          {overdueCount} visit{overdueCount === 1 ? '' : 's'} still open from
          before today.
        </p>
      )}

      {isError ? (
        <p className="text-[13px] text-destructive">
          Could not load your schedule.
        </p>
      ) : (
        <AppointmentsCalendar
          days={days}
          isEmpty={isEmpty}
          isBusy={isFetching}
          onComplete={openComplete}
        />
      )}

      <CompleteAppointmentModal
        appointment={pending}
        isSaving={isCompleting}
        onClose={closeComplete}
        onSubmit={submitComplete}
      />
    </div>
  );
}
