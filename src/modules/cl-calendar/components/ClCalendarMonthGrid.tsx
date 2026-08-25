import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { ChevronLeft, ChevronRight } from 'lucide-react';
import { calendarColorFor } from '@/modules/appointments';
import type { CalendarColorMap } from '@/modules/appointments';
import { Card } from '@/shared/ui/core';
import {
  DAY_CELL_BASE,
  DAY_NUMBER_BASE,
  SELECTED_DAY_CELL,
} from '@/shared/ui/data-display';
import { cn } from '@/shared/utils/cn';
import {
  CL_MAX_CHIPS_PER_DAY,
} from '../constants/clCalendarConstants';
import type { ClCalendarCell, ClCalendarEvent } from '../types/clCalendarTypes';
import {
  CL_WEEKDAY_LABELS,
  clMonthLabel,
  clShortTime,
} from '../utils/clCalendarUtils';

interface ClCalendarMonthGridProps {
  month: Date;
  cells: readonly ClCalendarCell[];
  selectedKey: string;
  isFetching: boolean;
  /**
   * userId → chosen hex. In "my calendar" scope this holds just the session
   * user's own colour, which useTenantCalendarColors supplies from the auth
   * slice without a request — so a personal calendar still paints the colour
   * its owner picked. See that hook.
   */
  colors: CalendarColorMap;
  onPrevMonth: () => void;
  onNextMonth: () => void;
  onToday: () => void;
  onSelectDay: (key: string) => void;
}

/**
 * The month grid, mirroring the HospiceLink calendar's structure so the two
 * products' calendars read as one product: one continuous hairline grid, 42
 * cells, day number centred at the top, compact event chips.
 *
 * Colour is per-OWNER (via the shared calendar palette), not per-status. The
 * guide's promise for this screen is "the whole team's, color-coded by person",
 * and a hue that means both "Sarah" and "cancelled" can mean neither. Cancelled
 * rows are struck through instead.
 */
export function ClCalendarMonthGrid({
  month,
  cells,
  selectedKey,
  isFetching,
  colors,
  onPrevMonth,
  onNextMonth,
  onToday,
  onSelectDay,
}: ClCalendarMonthGridProps) {
  /**
   * The owner's colour, in EVERY scope.
   *
   * This used to return a flat `bg-primary/[0.14] text-primary` tint whenever
   * the scope was "my calendar", on the reasoning that every row there is yours
   * so a per-owner hue carries no information. That reasoning holds for telling
   * people apart, but it breaks a promise made elsewhere: the profile page's
   * colour picker says "how your appointments are marked on the calendar", and
   * the CommunityLink guide says "change your own calendar color anytime from
   * your profile settings". A user who picks a colour and then opens the
   * calendar they land on by default saw the generic accent — which reads as
   * the setting having done nothing.
   *
   * The colour is still not carrying identity on a personal calendar; it is
   * carrying the user's own choice, which is a different job and a real one.
   */
  const chipStyle = (event: ClCalendarEvent) =>
    calendarColorFor(event.ownerId, colors[event.ownerId ?? '']).dot;

  return (
    <Card className="overflow-hidden">
      <header className="flex items-center gap-3 px-4 py-3">
        <h2 className={SECTION_TITLE}>
          {clMonthLabel(month)}
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
            className="border-x border-border/[0.12] px-3 py-1 text-[11px] font-bold uppercase tracking-label text-muted transition hover:bg-foreground/[0.05] hover:text-foreground"
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
        {isFetching && (
          <span className="text-[10px] uppercase tracking-label text-muted-soft">
            Updating…
          </span>
        )}
      </header>

      <div className="grid grid-cols-7 border-y border-border/[0.09]">
        {CL_WEEKDAY_LABELS.map((label) => (
          <div
            key={label}
            className="py-1.5 text-center text-[10px] font-bold uppercase tracking-label text-muted-soft"
          >
            <span className="hidden sm:inline">{label}</span>
            <span className="sm:hidden">{label.charAt(0)}</span>
          </div>
        ))}
      </div>

      <div className="-mb-px -mr-px grid grid-cols-7 [grid-auto-rows:minmax(84px,1fr)]">
        {cells.map((cell) => (
          <button
            key={cell.key}
            type="button"
            onClick={() => onSelectDay(cell.key)}
            aria-current={cell.isToday ? 'date' : undefined}
            aria-pressed={selectedKey === cell.key}
            className={cn(
              DAY_CELL_BASE,
              selectedKey === cell.key && SELECTED_DAY_CELL,
            )}
          >
            <span className="flex justify-center">
              <span
                className={cn(
                  DAY_NUMBER_BASE,
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
              {cell.items.slice(0, CL_MAX_CHIPS_PER_DAY).map((event) => (
                <span
                  key={event.id}
                  title={`${event.title}${event.detail ? ` — ${event.detail}` : ''}`}
                  className={cn(
                    'flex items-baseline gap-1 truncate rounded-[4px] px-1.5 py-[2px] text-[10px] font-semibold leading-[14px]',
                    chipStyle(event),
                    // `chipStyle` is always a solid owner fill now, so the label
                    // is always the on-fill colour. It used to be conditional
                    // because the personal-scope branch returned a pale tint
                    // that needed dark text instead.
                    'text-white',
                    event.isCancelled && 'line-through opacity-70',
                  )}
                >
                  {event.hasTime && (
                    <span className="shrink-0 tabular-nums opacity-90">
                      {clShortTime(event.at)}
                    </span>
                  )}
                  <span className="truncate">{event.title}</span>
                </span>
              ))}
              {cell.items.length > CL_MAX_CHIPS_PER_DAY && (
                <span className="px-1.5 text-[10px] font-semibold text-muted">
                  +{cell.items.length - CL_MAX_CHIPS_PER_DAY} more
                </span>
              )}
            </span>
          </button>
        ))}
      </div>
    </Card>
  );
}
