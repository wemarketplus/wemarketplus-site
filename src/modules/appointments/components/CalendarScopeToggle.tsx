import { cn } from '@/shared/utils/cn';
import type { CalendarScope } from '../hooks/useAppointmentsCalendar';

interface CalendarScopeToggleProps {
  scope: CalendarScope;
  onChange: (scope: CalendarScope) => void;
}

const OPTIONS: ReadonlyArray<{ value: CalendarScope; label: string }> = [
  { value: 'mine', label: 'My calendar' },
  { value: 'all', label: 'All users' },
];

/**
 * My calendar / All users.
 *
 * "Mine" is the default because the calendar is primarily a work surface, and a
 * marketer opening it wants their own day rather than the team's. Switching to
 * "All users" is what turns it into a coordination view — and is the only mode
 * where the per-user colours mean anything.
 */
export function CalendarScopeToggle({
  scope,
  onChange,
}: CalendarScopeToggleProps) {
  return (
    <div
      role="group"
      aria-label="Calendar scope"
      className="inline-flex gap-1.5"
    >
      {OPTIONS.map((option) => (
        <button
          key={option.value}
          type="button"
          aria-pressed={scope === option.value}
          onClick={() => onChange(option.value)}
          className={cn(
            'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-label transition-colors',
            scope === option.value
              ? 'border-primary/40 bg-primary/15 text-primary'
              : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}
