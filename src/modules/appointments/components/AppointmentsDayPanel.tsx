import { CalendarPlus, Clock, MapPin, User, Video } from 'lucide-react';
import type { FollowUpItem } from '@/modules/activity/hooks/useFollowUps';
import { Button, Card } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import {
  APPOINTMENT_OUTCOME_LABELS,
  APPOINTMENT_STATUS_LABELS,
  APPOINTMENT_TYPE_LABELS,
} from '../constants/appointmentsConstants';
import {
  AppointmentStatus,
  AppointmentType,
  type AppointmentRecord,
} from '../types/appointmentsTypes';
import { isCompletable, timeRange } from '../utils/appointmentsUtils';

/** Left rail colour per status — mirrors the month-grid chip fills. */
const STATUS_RAIL: Record<AppointmentStatus, string> = {
  [AppointmentStatus.Scheduled]: 'bg-azure',
  [AppointmentStatus.Completed]: 'bg-success',
  [AppointmentStatus.NoShow]: 'bg-destructive',
  [AppointmentStatus.Cancelled]: 'bg-muted',
  [AppointmentStatus.Rescheduled]: 'bg-warning',
};

const STATUS_TEXT: Record<AppointmentStatus, string> = {
  [AppointmentStatus.Scheduled]: 'text-azure',
  [AppointmentStatus.Completed]: 'text-success',
  [AppointmentStatus.NoShow]: 'text-destructive',
  [AppointmentStatus.Cancelled]: 'text-muted',
  [AppointmentStatus.Rescheduled]: 'text-warning',
};

/** Long-form heading for the selected day, e.g. "Thursday, 30 July". */
function dayHeading(dateKey: string): string {
  // dateKey is YYYY-MM-DD; construct in local time so the label can't slip a day.
  const [year, month, day] = dateKey.split('-').map(Number);
  return new Date(year, month - 1, day).toLocaleDateString(undefined, {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
  });
}

interface AppointmentsDayPanelProps {
  dateKey: string | null;
  items: readonly AppointmentRecord[];
  /** Follow-ups due on this day — reminders, not visits. Listed after the visits. */
  followUps?: readonly FollowUpItem[];
  isBusy: boolean;
  onComplete: (appointment: AppointmentRecord) => void;
  /**
   * Omitted for roles that cannot create an appointment (no pipeline access means
   * no job to hang one off). Their calendar is self-scoped and usually empty, so
   * this empty state is the first thing they see — offering an action that always
   * fails would be the worst place to put one.
   */
  onSchedule?: () => void;
}

/** The selected day's detail, beside the month grid. */
export function AppointmentsDayPanel({
  dateKey,
  items,
  followUps = [],
  isBusy,
  onComplete,
  onSchedule,
}: AppointmentsDayPanelProps) {
  return (
    <Card className="flex h-fit flex-col overflow-hidden">
      <header className="flex items-baseline justify-between gap-2 px-4 py-3">
        <h2 className="text-[13px] font-extrabold text-foreground">
          {dateKey ? dayHeading(dateKey) : 'Select a day'}
        </h2>
        {items.length > 0 && (
          <span className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
            {items.length} visit{items.length === 1 ? '' : 's'}
          </span>
        )}
      </header>

      {/* "Nothing scheduled" is only honest when there are no follow-ups either —
          a day holding a promise to ring a family back is not an empty day. */}
      {items.length === 0 && followUps.length === 0 ? (
        // Compact empty state with the obvious next action — not a tall blank void.
        <div className="flex flex-col items-start gap-2 border-t border-border/[0.09] px-4 py-4">
          <p className="text-xs text-muted">Nothing scheduled.</p>
          {onSchedule && (
            <Button variant="ghost" onClick={onSchedule}>
              <CalendarPlus className="h-4 w-4" /> Schedule
            </Button>
          )}
        </div>
      ) : (
        <ul className="divide-y divide-border/[0.09] border-t border-border/[0.09]">
          {items.map((appointment) => (
            <li key={appointment.id} className="flex gap-2.5 px-4 py-3">
              {/* Colour rail ties the row to its chip in the grid. */}
              <span
                className={cn(
                  'mt-0.5 w-[3px] shrink-0 rounded-full',
                  STATUS_RAIL[appointment.status],
                )}
              />
              <div className="min-w-0 flex-1 space-y-1">
                <p className="text-sm font-bold leading-snug text-foreground">
                  {appointment.title}
                </p>
                {/* Who the visit is for. The panel gave a time, a place and a
                    status but never a person, so "click into any visit for the
                    patient details before you head out" had nothing to read. */}
                {appointment.patientName && (
                  <p className="flex items-center gap-1.5 text-[11px] font-semibold text-foreground">
                    <User className="h-3 w-3 shrink-0 text-muted" />
                    {appointment.patientName}
                  </p>
                )}
                <p className="flex items-center gap-1.5 text-[11px] text-muted">
                  <Clock className="h-3 w-3 shrink-0" />
                  {timeRange(appointment)}
                  <span className="text-muted-soft">·</span>
                  {appointment.appointmentType === AppointmentType.Virtual ? (
                    <Video className="h-3 w-3 shrink-0" />
                  ) : null}
                  {APPOINTMENT_TYPE_LABELS[appointment.appointmentType]}
                </p>
                {appointment.location && (
                  <p className="flex items-start gap-1.5 text-[11px] text-muted">
                    <MapPin className="mt-[1px] h-3 w-3 shrink-0" />
                    <span className="min-w-0 break-words">
                      {appointment.location}
                    </span>
                  </p>
                )}
                <p
                  className={cn(
                    'text-[10px] font-bold uppercase tracking-[0.08em]',
                    STATUS_TEXT[appointment.status],
                  )}
                >
                  {APPOINTMENT_STATUS_LABELS[appointment.status]}
                  {appointment.outcome &&
                    ` · ${APPOINTMENT_OUTCOME_LABELS[appointment.outcome]}`}
                </p>
                {appointment.nextJobId && (
                  <p className="text-[10px] text-muted-soft">
                    Follow-up job created
                  </p>
                )}
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

          {/* Follow-ups after the visits, visually distinct: a dashed amber rail
              rather than a status colour, and no "Log visit" — there is no visit to
              log. They are closed from Reminders or Daily tasks. */}
          {followUps.map((followUp) => (
            <li key={followUp.id} className="flex gap-2.5 px-4 py-3">
              <span className="mt-0.5 w-[3px] shrink-0 rounded-full bg-warning" />
              <div className="min-w-0 flex-1 space-y-1">
                <p className="text-sm font-bold leading-snug text-foreground">
                  {followUp.title}
                </p>
                {followUp.patientName && (
                  <p className="flex items-center gap-1.5 text-[11px] font-semibold text-foreground">
                    <User className="h-3 w-3 shrink-0 text-muted" />
                    {followUp.patientName}
                  </p>
                )}
                {followUp.detail && (
                  <p className="text-[11px] text-muted">{followUp.detail}</p>
                )}
                <p className="text-[10px] font-bold uppercase tracking-[0.08em] text-warning">
                  Follow-up
                </p>
              </div>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
