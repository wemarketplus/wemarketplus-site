import { ChevronLeft, ChevronRight } from 'lucide-react';
import { calendarColorFor } from '@/modules/appointments';
import type { CalendarColorMap } from '@/modules/appointments';
import { Card } from '@/shared/ui/core';
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
  /** userId → chosen hex. Empty in "my calendar" scope, where colour says nothing. */
  colors: CalendarColorMap;
  /** True in "All users" scope — colours rows by owner. */
  showOwnerColors: boolean;
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
  showOwnerColors,
  onPrevMonth,
  onNextMonth,
  onToday,
  onSelectDay,
}: ClCalendarMonthGridProps) {
  const chipStyle = (event: ClCalendarEvent) => {
    if (!showOwnerColors) {
      // Personal calendar: one accent for everything. Every row is yours, so a
      // per-owner hue would be decoration carrying no information.
      return 'bg-primary/[0.14] text-primary';
    }
    return calendarColorFor(event.ownerId, colors[event.ownerId ?? '']).dot;
  };

  return (
    <Card className="overflow-hidden">
      <header className="flex items-center gap-3 px-4 py-3">
        <h2 className="text-[15px] font-extrabold text-foreground">
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
        {isFetching && (
          <span className="text-[10px] uppercase tracking-[0.1em] text-muted-soft">
            Updating…
          </span>
        )}
      </header>

      <div className="grid grid-cols-7 border-y border-border/[0.09]">
        {CL_WEEKDAY_LABELS.map((label) => (
          <div
            key={label}
            className="py-1.5 text-center text-[10px] font-bold uppercase tracking-[0.1em] text-muted-soft"
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
              'flex flex-col items-stretch gap-1 border-b border-r border-border/[0.09] bg-surface px-1 pb-1 pt-1 text-left transition hover:bg-foreground/[0.035]',
              selectedKey === cell.key &&
                'bg-primary/[0.06] ring-1 ring-inset ring-primary/40',
            )}
          >
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
              {cell.items.slice(0, CL_MAX_CHIPS_PER_DAY).map((event) => (
                <span
                  key={event.id}
                  title={`${event.title}${event.detail ? ` — ${event.detail}` : ''}`}
                  className={cn(
                    'flex items-baseline gap-1 truncate rounded-[4px] px-1.5 py-[2px] text-[10px] font-semibold leading-[14px]',
                    chipStyle(event),
                    showOwnerColors && 'text-white',
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
