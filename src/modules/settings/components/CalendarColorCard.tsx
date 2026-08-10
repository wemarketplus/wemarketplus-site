import { Check, Sparkles } from 'lucide-react';
import { useAppSelector } from '@/app/hooks';
// Deep import rather than the module barrel: the barrel re-exports
// AppointmentsPage, and a profile page has no business pulling the whole
// calendar module into its chunk to read eight hex values.
import {
  CALENDAR_PALETTE,
  calendarColorFor,
} from '@/modules/appointments/utils/calendarColors';
import { Card, CardContent } from '@/shared/ui/core';
import { cn } from '@/shared/utils/cn';
import { useCalendarColor } from '../hooks/useCalendarColor';

/**
 * "Want to change your own colour on the shared calendar? Pick a new one."
 *
 * A fixed palette of swatches, NOT a free colour input. The colour's only job is
 * to tell reps apart at a glance on the "All users" calendar, and an open picker
 * defeats that in two ways: two people choose near-identical shades, and someone
 * eventually chooses one with no contrast against the row. Eight distinguishable
 * hues is the constraint that makes the feature work.
 *
 * Saves on click rather than behind a Save button — see useCalendarColor.
 */
export function CalendarColorCard() {
  const userId = useAppSelector((s) => s.auth.user?.id ?? null);
  const { current, select, isSaving } = useCalendarColor();

  // What the calendar draws for this user right now: their choice if they have
  // made one, otherwise the colour derived from their id. Showing the derived
  // colour (rather than a blank) is the point — "your current colour" has to be
  // truthful for someone who has never opened this page.
  const effective = calendarColorFor(userId, current);

  return (
    <Card>
      <CardContent className="px-6 py-6">
        <header className="mb-6 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-base font-semibold text-foreground">
              Calendar colour
            </h2>
            <p className="mt-1 text-sm text-muted">
              How your appointments are marked on the shared “All users”
              calendar.
            </p>
          </div>
          <div className="flex items-center gap-2 rounded-pill border border-border/[0.08] px-3 py-1.5">
            <span className={cn('h-2.5 w-2.5 rounded-full', effective.dot)} />
            <span className="text-[11px] font-semibold uppercase tracking-[0.08em] text-muted">
              {current ? 'Your colour' : 'Automatic'}
            </span>
          </div>
        </header>

        <div
          className="flex flex-wrap gap-2"
          role="radiogroup"
          aria-label="Calendar colour"
        >
          {CALENDAR_PALETTE.map((entry) => {
            const selected = current === entry.hex;
            return (
              <button
                key={entry.hex}
                type="button"
                role="radio"
                aria-checked={selected}
                aria-label={entry.label}
                title={entry.label}
                disabled={isSaving}
                onClick={() => void select(entry.hex)}
                className={cn(
                  'flex h-10 w-10 items-center justify-center rounded-full border-2 transition disabled:opacity-50',
                  entry.dot,
                  // The ring, not the fill, carries selection: the fill IS the
                  // choice, so it can't also encode whether it was chosen.
                  selected
                    ? 'border-foreground'
                    : 'border-transparent hover:border-border/40',
                )}
              >
                {selected && <Check className="h-4 w-4 text-white" />}
              </button>
            );
          })}
        </div>

        <button
          type="button"
          disabled={isSaving || current === null}
          onClick={() => void select(null)}
          className={cn(
            'mt-5 inline-flex items-center gap-2 rounded-pill border px-3.5 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
            current === null
              ? 'border-primary/40 bg-primary/15 text-primary'
              : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
            'disabled:cursor-default',
          )}
        >
          <Sparkles className="h-3.5 w-3.5" />
          {current === null ? 'Using automatic colour' : 'Use automatic colour'}
        </button>

        <p className="mt-3 text-xs text-muted-soft">
          Automatic picks a stable colour from your account, so you always have
          one even if you never choose. Colours are a visual hint — teammates may
          share one, and it never signals status or priority.
        </p>
      </CardContent>
    </Card>
  );
}
