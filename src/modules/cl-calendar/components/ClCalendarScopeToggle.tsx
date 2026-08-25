import { Info } from 'lucide-react';
import { Select } from '@/shared/ui/core';
import type { ClCalendarScope } from '../types/clCalendarTypes';

interface ClCalendarScopeToggleProps {
  scope: ClCalendarScope;
  onChange: (scope: ClCalendarScope) => void;
}

interface ClCalendarUnassignedNoteProps {
  scope: ClCalendarScope;
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
export function ClCalendarScopeToggle({ scope, onChange }: ClCalendarScopeToggleProps) {
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
    </div>
  );
}

/**
 * THE CAVEAT NOTE, AND WHY IT IS NO LONGER PART OF THE CONTROL ABOVE.
 *
 * It used to be the third child of that block, rendered only in `mine` scope.
 * The page header is a `flex … items-end` row, so the two children hang from
 * their BOTTOM edges — which meant the note appearing added its own height to
 * the block and pushed the <Select> upward by exactly that much. Switching
 * between "All users" and "My calendar" therefore moved the dropdown, every
 * time, reproducibly: the reported "user dropdown changes position".
 *
 * The fix is structural rather than a width or an alignment tweak — a control
 * cannot share a bottom-aligned box with a sibling that comes and goes. So the
 * note is now rendered by the page BELOW the header, full width. It still
 * appears and disappears with scope, but where it does so nothing is anchored to
 * it, and the layout change is ordinary flow (the calendar card moves down a
 * line) rather than a control jumping.
 *
 * Kept in this file, beside the control it explains, so the copy and the reason
 * for it do not drift apart. Returns null when it does not apply, so the caller
 * carries no condition of its own.
 *
 * The wording: this note used to be about outreach visits, on the belief that
 * they had no owner in the API. They do (`userId`, set from the caller), and "My
 * calendar" filters them correctly — so that version was not just stale, it was
 * actively misleading, telling a marketer their own logged visits were nobody's.
 * What is left is the genuinely unassigned tour, since `cl_tours.guideUserId` is
 * nullable and both tour forms offer "— Unassigned —".
 */
export function ClCalendarUnassignedNote({
  scope,
  hasUnownedEvents,
}: ClCalendarUnassignedNoteProps) {
  if (scope !== 'mine' || !hasUnownedEvents) return null;
  return (
    <p className="flex items-start gap-1.5 text-[11px] leading-snug text-muted-soft">
      <Info className="mt-px h-3 w-3 shrink-0" />
      Tours with no guide assigned are shown to everyone, so they are not missed.
    </p>
  );
}
