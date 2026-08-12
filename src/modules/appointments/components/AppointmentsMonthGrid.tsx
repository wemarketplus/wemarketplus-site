import { ChevronLeft, ChevronRight } from 'lucide-react';
import { Card } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import {
  APPOINTMENT_STATUS_LABELS,
  APPOINTMENT_TYPE_LABELS,
} from '../constants/appointmentsConstants';
import {
  AppointmentStatus,
  type AppointmentRecord,
} from '../types/appointmentsTypes';
import { calendarColorFor } from '../utils/calendarColors';
import {
  WEEKDAY_LABELS,
  monthLabel,
  type CalendarCell,
} from '../utils/appointmentsUtils';

/**
 * Solid event fills with white text, the way Google Calendar renders month-view
 * events — but the fill is now the OWNER'S CHOSEN COLOUR, not the status.
 *
 * The block used to be painted by status (azure = scheduled, green = completed…)
 * and the colour a user picked for themselves appeared nowhere on this view, so
 * choosing one looked like it did nothing. The colour is the point of the
 * setting, so it gets the fill; status keeps the marks below plus the full text
 * label in the day panel and the chip's own tooltip.
 */
const STATUS_MARK: Partial<Record<AppointmentStatus, string>> = {
  // A cancelled visit must never read as a live one, whatever colour its owner
  // picked — this is the one status the block still has to state on sight.
  [AppointmentStatus.Cancelled]: 'line-through opacity-60',
  // Didn't happen, but not called off: dimmed without the strikethrough.
  [AppointmentStatus.NoShow]: 'opacity-75',
};

/** Appointments rendered per cell before collapsing into a "+N more" line. */
const MAX_CHIPS_PER_DAY = 2;

/** "10:00 AM" -> "10a" (Google's compact month-view time). */
const shortTime = (iso: string): string => {
  const date = new Date(iso);
  const hour = date.getHours();
  const minute = date.getMinutes();
  const suffix = hour < 12 ? 'a' : 'p';
  const base = hour % 12 === 0 ? 12 : hour % 12;
  return minute === 0
    ? `${base}${suffix}`
    : `${base}:${String(minute).padStart(2, '0')}${suffix}`;
};

interface AppointmentsMonthGridProps {
  month: Date;
  cells: readonly CalendarCell[];
  selectedKey: string | null;
  isFetching: boolean;
  onPrevMonth: () => void;
  onNextMonth: () => void;
  onToday: () => void;
  onSelectDay: (key: string) => void;
  onOpenAppointment: (appointment: AppointmentRecord) => void;
  /**
   * userId -> chosen `#rrggbb`. Drives the owner stripe on each chip.
   *
   * The chip FILL stays the status colour: "whose visit is this" and "did it
   * happen" are two different questions, and this view answered only the second
   * — so a user who set a calendar colour saw nothing change on the view the
   * page actually opens on. The stripe adds the first answer without spending
   * the fill, which is why it is a stripe and not a recolour.
   */
  ownerColorMap?: Readonly<Record<string, string>>;
}

export function AppointmentsMonthGrid({
  month,
  cells,
  selectedKey,
  isFetching,
  onPrevMonth,
  onNextMonth,
  onToday,
  onSelectDay,
  onOpenAppointment,
  ownerColorMap,
}: AppointmentsMonthGridProps) {
  return (
    <Card className="overflow-hidden">
      {/* Toolbar — month label and its nav read as one control. */}
      <header className="flex items-center gap-3 px-4 py-3">
        <h2 className="text-[15px] font-extrabold text-foreground">
          {monthLabel(month)}
        </h2>
        <div className="flex items-center overflow-hidden rounded-pill border border-border/[0.12]">
          <button
            type="button"
            aria-label="Previous month"
            onClick={onPrevMonth}
            className="px-2 py-1 text-muted transition hover:bg-foreground/[0.05] hover:text-foreground"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <button
            type="button"
            onClick={onToday}
            className="border-x border-border/[0.12] px-3 py-1 text-[11px] font-bold uppercase tracking-[0.08em] text-muted transition hover:bg-foreground/[0.05] hover:text-foreground"
          >
            Today
          </button>
          <button
            type="button"
            aria-label="Next month"
            onClick={onNextMonth}
            className="px-2 py-1 text-muted transition hover:bg-foreground/[0.05] hover:text-foreground"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
        {/* Month switches refetch; surface it without collapsing the grid. */}
        {isFetching && (
          <span className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
            Updating…
          </span>
        )}
      </header>

      {/* Weekday rail — centered, no fill, hairline under it. */}
      <div className="grid grid-cols-7 border-y border-border/[0.09]">
        {WEEKDAY_LABELS.map((label) => (
          <div
            key={label}
            className="py-1.5 text-center text-[10px] font-bold uppercase tracking-[0.1em] text-muted-soft"
          >
            <span className="hidden sm:inline">{label}</span>
            <span className="sm:hidden">{label.charAt(0)}</span>
          </div>
        ))}
      </div>

      {/*
        ONE continuous grid with hairline dividers — not 42 rounded cards.
        `-mb-px -mr-px` swallows the trailing edges so the Card border isn't
        doubled. Rows share height via grid-auto-rows so the month never jitters.
      */}
      <div className="-mb-px -mr-px grid grid-cols-7 [grid-auto-rows:minmax(84px,1fr)]">
        {cells.map((cell) => {
          const isSelected = selectedKey === cell.key;
          return (
            <button
              key={cell.key}
              type="button"
              onClick={() => onSelectDay(cell.key)}
              aria-current={cell.isToday ? 'date' : undefined}
              aria-pressed={isSelected}
              className={cn(
                'flex flex-col items-stretch gap-1 border-b border-r border-border/[0.09] px-1 pb-1 pt-1 text-left transition',
                // Google keeps out-of-month cells white and only greys the number.
                'bg-surface hover:bg-foreground/[0.035]',
                isSelected && 'bg-primary/[0.06] ring-1 ring-inset ring-primary/40',
              )}
            >
              {/* Day number: centered at the top, like Google's month view. */}
              <span className="flex justify-center">
                <span
                  className={cn(
                    'inline-flex h-[21px] min-w-[21px] items-center justify-center rounded-full px-1 text-[11px] font-semibold tabular-nums leading-none',
                    cell.isToday
                      ? 'bg-primary font-bold text-primary-foreground'
                      : cell.inMonth
                        ? 'text-foreground'
                        : 'text-muted-soft',
                  )}
                >
                  {cell.date.getDate()}
                </span>
              </span>

              <span className="flex flex-col gap-[2px]">
                {cell.items.slice(0, MAX_CHIPS_PER_DAY).map((appointment) => (
                  <span
                    key={appointment.id}
                    role="button"
                    tabIndex={0}
                    title={`${appointment.title} — ${
                      APPOINTMENT_TYPE_LABELS[appointment.appointmentType]
                    } · ${APPOINTMENT_STATUS_LABELS[appointment.status]}`}
                    onClick={(event) => {
                      // Don't let the cell's day-select swallow the chip click.
                      event.stopPropagation();
                      onOpenAppointment(appointment);
                    }}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.stopPropagation();
                        onOpenAppointment(appointment);
                      }
                    }}
                    className={cn(
                      'flex items-baseline gap-1 truncate rounded-[4px] px-1.5 py-[2px] text-[10px] font-semibold leading-[14px] text-white transition hover:opacity-90',
                      calendarColorFor(
                        appointment.assignedRep,
                        appointment.assignedRep
                          ? ownerColorMap?.[appointment.assignedRep]
                          : null,
                      ).dot,
                      STATUS_MARK[appointment.status],
                    )}
                  >
                    <span className="shrink-0 tabular-nums opacity-90">
                      {shortTime(appointment.startAt)}
                    </span>
                    <span className="truncate">{appointment.title}</span>
                  </span>
                ))}
                {cell.items.length > MAX_CHIPS_PER_DAY && (
                  <span className="px-1.5 text-[10px] font-semibold text-muted">
                    +{cell.items.length - MAX_CHIPS_PER_DAY} more
                  </span>
                )}

                {/* Follow-ups sit BELOW the visits and look deliberately unlike
                    them — outlined rather than filled, a dot instead of a time,
                    because a follow-up is a promise to make contact, not a booked
                    visit with a slot. Not clickable: there is nothing to complete
                    here, the reminder is closed from Reminders or Daily tasks. */}
                {cell.followUps.slice(0, MAX_CHIPS_PER_DAY).map((followUp) => (
                  <span
                    key={followUp.id}
                    title={`Follow-up · ${followUp.title}${
                      followUp.patientName ? ` · ${followUp.patientName}` : ''
                    }${followUp.detail ? ` — ${followUp.detail}` : ''}`}
                    className="flex items-baseline gap-1 truncate rounded-[4px] border border-dashed border-warning/60 bg-warning/[0.08] px-1.5 py-[2px] text-[10px] font-semibold leading-[14px] text-warning"
                  >
                    <span aria-hidden className="shrink-0">
                      •
                    </span>
                    <span className="truncate">
                      {followUp.patientName ?? followUp.title}
                    </span>
                  </span>
                ))}
                {cell.followUps.length > MAX_CHIPS_PER_DAY && (
                  <span className="px-1.5 text-[10px] font-semibold text-muted">
                    +{cell.followUps.length - MAX_CHIPS_PER_DAY} more follow-ups
                  </span>
                )}
              </span>
            </button>
          );
        })}
      </div>
    </Card>
  );
}
