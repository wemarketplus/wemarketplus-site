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
        className="block text-[10px] font-bold uppercase tracking-label text-muted-soft"
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
        Says out loud why a row that is not yours is on "My calendar", rather
        than letting it look like a broken filter.

        This note used to be about outreach visits, on the belief that they had
        no owner in the API. They do (`userId`, set from the caller), and "My
        calendar" filters them correctly now — so that wording was not just
        stale, it was actively misleading: it told a marketer their own logged
        visits were nobody's. What is left is the genuinely unassigned tour,
        since `cl_tours.guideUserId` is nullable and the tour forms offer
        "— Unassigned —".
      */}
      {scope === 'mine' && hasUnownedEvents && (
        <p className="flex items-start gap-1.5 text-[11px] leading-snug text-muted-soft">
          <Info className="mt-px h-3 w-3 shrink-0" />
          Tours with no guide assigned are shown to everyone, so they are not
          missed.
        </p>
      )}
    </div>
  );
}
