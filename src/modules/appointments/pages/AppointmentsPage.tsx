import { Plus } from 'lucide-react';
import { useListJobsQuery } from '@/modules/jobs';
import { Button } from '@/shared/ui/core';
import { AppointmentsCalendar } from '../components/AppointmentsCalendar';
import { CompleteAppointmentModal } from '../components/CompleteAppointmentModal';
import { ScheduleAppointmentModal } from '../components/ScheduleAppointmentModal';
import { useAppointmentActions } from '../hooks/useAppointmentActions';
import { useAppointmentsCalendar } from '../hooks/useAppointmentsCalendar';

/** The real appointment calendar, backed by hl_appointments. */
export function AppointmentsPage() {
  const { days, isEmpty, isLoading, isError, appointments } =
    useAppointmentsCalendar();
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

  return (
    <div className="space-y-6">
      <header className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Appointments</h1>
          <p className="text-sm text-muted">
            {appointments.length} scheduled in the next 60 days
          </p>
        </div>
        <Button onClick={openSchedule}>
          <Plus className="h-4 w-4" /> Schedule appointment
        </Button>
      </header>

      {isError && (
        <p className="rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">
          Could not load the calendar.
        </p>
      )}

      {isLoading ? (
        <p className="text-sm text-muted-soft">Loading calendar…</p>
      ) : (
        <AppointmentsCalendar
          days={days}
          isEmpty={isEmpty}
          isBusy={isCompleting}
          onComplete={openComplete}
        />
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
