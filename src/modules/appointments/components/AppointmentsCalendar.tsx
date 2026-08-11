import { Button, Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { formatDate } from '@/shared/utils/dateFormatter';
import { cn } from '@/shared/utils/cn';
import {
  APPOINTMENT_OUTCOME_LABELS,
  APPOINTMENT_STATUS_LABELS,
  APPOINTMENT_STATUS_PILL,
  APPOINTMENT_TYPE_LABELS,
} from '../constants/appointmentsConstants';
import type { AppointmentRecord } from '../types/appointmentsTypes';
import { isCompletable, isPastDue, timeRange } from '../utils/appointmentsUtils';
import { calendarColorFor } from '../utils/calendarColors';

interface AppointmentsCalendarProps {
  days: ReadonlyArray<{ date: string; items: AppointmentRecord[] }>;
  isEmpty: boolean;
  isBusy: boolean;
  onComplete: (appointment: AppointmentRecord) => void;
  /**
   * When true, each row is colour-coded by its assigned rep. Only meaningful in
   * the "All users" view — in a personal calendar every row is the same person,
   * so a colour would carry no information.
   */
  showOwnerColors?: boolean;
  /**
   * userId -> the colour that user chose in their profile settings. Optional:
   * omit it and every row falls back to the colour derived from the rep's id,
   * which is what this calendar did before colours could be chosen.
   */
  ownerColorMap?: Readonly<Record<string, string>>;
}

/** Day-grouped agenda over the real appointments feed. */
export function AppointmentsCalendar({
  days,
  isEmpty,
  isBusy,
  onComplete,
  showOwnerColors = false,
  ownerColorMap,
}: AppointmentsCalendarProps) {
  if (isEmpty) {
    return (
      <Card>
        <CardContent className="px-6 py-6">
          <p className="text-xs text-muted-soft">
            No appointments scheduled in this window.
          </p>
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      {days.map((day) => (
        <Card key={day.date}>
          <CardContent className="px-0 pt-0 pb-0">
            <header className="px-6 py-3">
              <p className="text-[10px] uppercase tracking-[0.14em] text-muted-soft">
                {formatDate(day.date)}
              </p>
            </header>
            <ul className="divide-y divide-border">
              {day.items.map((appointment) => (
                <li
                  key={appointment.id}
                  className="flex flex-wrap items-start gap-3 px-6 py-3"
                >
                  {/* Past-due always wins over the owner colour: "this was
                      missed" is more urgent than "this is Dana's". */}
                  <span
                    className={cn(
                      'mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full',
                      isPastDue(appointment)
                        ? 'bg-destructive'
                        : showOwnerColors
                          ? calendarColorFor(
                              appointment.assignedRep,
                              appointment.assignedRep
                                ? ownerColorMap?.[appointment.assignedRep]
                                : null,
                            ).dot
                          : 'bg-primary',
                    )}
                  />
                  <div className="min-w-0 flex-1">
                    <p className="text-sm font-semibold text-foreground">
                      {appointment.title}
                      {/* The patient reads as part of the visit's identity, not as
                          metadata below it: on a nurse's own agenda, "Home visit"
                          alone does not say which home. */}
                      {appointment.patientName && (
                        <span className="font-normal text-muted">
                          {' · '}
                          {appointment.patientName}
                        </span>
                      )}
                    </p>
                    <p className="mt-0.5 text-xs text-muted">
                      {timeRange(appointment)} ·{' '}
                      {APPOINTMENT_TYPE_LABELS[appointment.appointmentType]}
                      {appointment.location ? ` · ${appointment.location}` : ''}
                    </p>
                    {appointment.outcome && (
                      <p className="mt-0.5 text-[11px] text-muted-soft">
                        Outcome:{' '}
                        {APPOINTMENT_OUTCOME_LABELS[appointment.outcome]}
                        {appointment.nextJobId && ' · follow-up job created'}
                      </p>
                    )}
                  </div>
                  <div className="flex shrink-0 items-center gap-2">
                    <Pill tone={APPOINTMENT_STATUS_PILL[appointment.status]}>
                      {APPOINTMENT_STATUS_LABELS[appointment.status]}
                    </Pill>
                    {isCompletable(appointment) && (
                      <Button
                        variant="ghost"
                        disabled={isBusy}
                        onClick={() => onComplete(appointment)}
                      >
                        Log visit
                      </Button>
                    )}
                  </div>
                </li>
              ))}
            </ul>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
