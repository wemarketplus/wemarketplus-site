import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { CalendarPlus, MapPin } from 'lucide-react';
import { Link } from 'react-router-dom';
import { calendarColorFor } from '@/modules/appointments';
import type { CalendarColorMap } from '@/modules/appointments';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { Pill } from '@/shared/ui/data-display';
import { cn } from '@/shared/utils/cn';
import { ClCalendarEventKind, type ClCalendarEvent } from '../types/clCalendarTypes';
import { clShortTime } from '../utils/clCalendarUtils';

interface ClCalendarDayPanelProps {
  /** `YYYY-MM-DD` of the selected cell. */
  dayKey: string;
  events: readonly ClCalendarEvent[];
  /**
   * userId → chosen hex. In "my calendar" scope this holds just the session
   * user's own colour (useTenantCalendarColors reads it from the auth slice with
   * no request), so a personal calendar still shows the colour its owner picked.
   */
  colors: CalendarColorMap;
  onSchedule: () => void;
}

/** "Tue, 11 August" from a `YYYY-MM-DD` key, without a UTC round trip. */
function dayHeading(dayKey: string): string {
  const [year, month, day] = dayKey.split('-').map(Number);
  return new Date(year, (month ?? 1) - 1, day ?? 1).toLocaleDateString(
    undefined,
    { weekday: 'short', day: 'numeric', month: 'long' },
  );
}

/**
 * The selected day, in full. The grid can only show two chips per cell, so this
 * is where a day with real activity is actually read — and where the primary
 * "Schedule" action lives, since scheduling is always for a particular day.
 */
export function ClCalendarDayPanel({
  dayKey,
  events,
  colors,
  onSchedule,
}: ClCalendarDayPanelProps) {
  return (
    <Card>
      <CardContent className="px-0 pb-0 pt-0">
        <header className="flex flex-wrap items-center gap-3 px-5 py-4">
          <div className="min-w-0 flex-1">
            <h2 className={SECTION_TITLE}>
              {dayHeading(dayKey)}
            </h2>
            <p className="text-[11px] text-muted-soft">
              {events.length === 0
                ? 'Nothing scheduled'
                : `${events.length} item${events.length === 1 ? '' : 's'}`}
            </p>
          </div>
          <Button size="sm" onClick={onSchedule}>
            <CalendarPlus className="h-4 w-4" />
            Schedule
          </Button>
        </header>

        {events.length === 0 ? (
          <p className="px-5 pb-5 text-xs text-muted-soft">
            Pick another day, or schedule a tour, facility visit or physician
            lunch on this one.
          </p>
        ) : (
          <ul className="border-t border-border/[0.09]">
            {events.map((event) => {
              const owner = calendarColorFor(
                event.ownerId,
                colors[event.ownerId ?? ''],
              );
              return (
                <li
                  key={event.id}
                  className="border-b border-border/[0.06] last:border-b-0"
                >
                  <Link
                    to={event.to}
                    className="flex items-start gap-3 px-5 py-3 transition-colors hover:bg-foreground/[0.03]"
                  >
                    {/* Owner dot — the legend for the grid's colour coding. */}
                    <span
                      // The owner's colour in every scope — on a personal
                      // calendar that is the user's own choice from their
                      // profile, which is the whole point of offering the
                      // picker. See chipStyle in ClCalendarMonthGrid.
                      className={cn(
                        'mt-1.5 h-2.5 w-2.5 shrink-0 rounded-full',
                        owner.dot,
                      )}
                    />
                    <div className="min-w-0 flex-1">
                      <p
                        className={cn(
                          'truncate text-[13px] font-semibold text-foreground',
                          event.isCancelled && 'line-through text-muted',
                        )}
                      >
                        {event.title}
                      </p>
                      <p className="truncate text-[11px] text-muted-soft">
                        {event.hasTime ? clShortTime(event.at) : 'All day'}
                        {event.detail && ` · ${event.detail}`}
                      </p>
                    </div>
                    <Pill
                      tone={
                        event.kind === ClCalendarEventKind.Tour ? 'b' : 'p'
                      }
                      className="shrink-0"
                    >
                      {event.kind === ClCalendarEventKind.Visit && (
                        <MapPin className="mr-1 inline h-3 w-3" />
                      )}
                      {/* The row's OWN type — "Lunch & learn", "Drop-off /
                          materials" — not the label of its kind, which cannot
                          tell a physician lunch from a facility visit because
                          both are the same table. */}
                      {event.typeLabel}
                    </Pill>
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
