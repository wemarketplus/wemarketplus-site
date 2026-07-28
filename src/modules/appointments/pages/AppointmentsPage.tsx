import { AppointmentsCalendar } from '../components/AppointmentsCalendar';
import { CompleteAppointmentModal } from '../components/CompleteAppointmentModal';
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
  } = useAppointmentActions();

  return (
    <div className="space-y-6">
      <header>
        <h1 className="font-display text-3xl text-foreground">Appointments</h1>
        <p className="text-sm text-muted">
          {appointments.length} scheduled in the next 60 days
        </p>
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

      <CompleteAppointmentModal
        appointment={pending}
        isSaving={isCompleting}
        onClose={closeComplete}
        onSubmit={(id, body) => void submitComplete(id, body)}
      />
    </div>
  );
}
