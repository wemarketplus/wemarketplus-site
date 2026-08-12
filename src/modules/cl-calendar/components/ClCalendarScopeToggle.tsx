import { Info } from 'lucide-react';
import { Select } from '@/shared/ui/core';
import type { ClCalendarScope } from '../types/clCalendarTypes';

interface ClCalendarScopeToggleProps {
  scope: ClCalendarScope;
  onChange: (scope: ClCalendarScope) => void;
  /** Drives the caveat note — see useClCalendar's scope note. */
  hasUnownedEvents: boolean;
}

/**
 * "Use the dropdown to switch between My Calendar (just your appointments) and
 * All Users (the whole team's, color-coded by person)."
 *
 * A real `<select>`, because the guide calls it a dropdown and a user following
 * the sentence should find one — not a segmented control that behaves like one.
 */
export function ClCalendarScopeToggle({
  scope,
  onChange,
  hasUnownedEvents,
}: ClCalendarScopeToggleProps) {
  return (
    <div className="space-y-1.5">
      <label
        htmlFor="cl-cal-scope"
        className="block text-[10px] font-bold uppercase tracking-[0.1em] text-muted-soft"
      >
        Viewing
      </label>
      <Select
        id="cl-cal-scope"
        value={scope}
        onChange={(event) => onChange(event.target.value as ClCalendarScope)}
        className="w-auto min-w-[11rem]"
      >
        <option value="mine">My calendar</option>
        <option value="all">All users</option>
      </Select>

      {/*
        Says out loud what "My calendar" cannot do, rather than quietly showing
        rows that are not yours. Outreach visits carry no owner in the API, so
        they appear in both scopes; a marketer who saw a colleague's drop-in on
        "My calendar" would otherwise reasonably think the filter was broken.
      */}
      {scope === 'mine' && hasUnownedEvents && (
        <p className="flex items-start gap-1.5 text-[11px] leading-snug text-muted-soft">
          <Info className="mt-px h-3 w-3 shrink-0" />
          Logged facility visits are shown to the whole team — they are not
          recorded against a person yet.
        </p>
      )}
    </div>
  );
}
