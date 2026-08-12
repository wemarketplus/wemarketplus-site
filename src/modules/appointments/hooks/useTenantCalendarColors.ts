import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
// Deep import (as useProfileForm does for the same api) so the calendar does not
// drag the users module's admin pages into its chunk.
import { useListCalendarColorsQuery } from '@/modules/users/api/usersApi';

/** userId -> chosen `#rrggbb`, for users who have chosen one. */
export type CalendarColorMap = Readonly<Record<string, string>>;

const EMPTY: CalendarColorMap = {};

/**
 * The tenant's chosen calendar colours, as a lookup the calendar can index by
 * assigned rep.
 *
 * `enabled` gates the NETWORK CALL, not the feature: only the "All users" view
 * needs everybody's choice, so a personal calendar keeps its previous zero extra
 * network cost. It still gets a colour, because the only one it can ever need —
 * the session user's own — is already in the auth slice. That matters: the
 * profile page's promise is "this is the colour your appointments are marked
 * in", and a user who picks one, returns to the calendar they open on and sees
 * nothing changed concludes the setting is broken.
 *
 * The session user's own choice is applied LAST so it wins over their own row in
 * a tenant list fetched before they changed it.
 *
 * Users who have not chosen are simply absent from the map, which is exactly
 * what `calendarColorFor(id, undefined)` wants — it derives their colour from
 * the id, as it always has.
 */
export function useTenantCalendarColors(enabled: boolean): CalendarColorMap {
  const { data } = useListCalendarColorsQuery(undefined, { skip: !enabled });
  const ownId = useAppSelector((s) => s.auth.user?.id ?? null);
  const ownColor = useAppSelector((s) => s.auth.user?.calendarColor ?? null);

  return useMemo(() => {
    const own: Record<string, string> =
      ownId && ownColor ? { [ownId]: ownColor } : {};
    if (!data) return ownId && ownColor ? own : EMPTY;
    const fromServer = data.reduce<Record<string, string>>((acc, entry) => {
      if (entry.calendarColor) acc[entry.userId] = entry.calendarColor;
      return acc;
    }, {});
    return { ...fromServer, ...own };
  }, [data, ownId, ownColor]);
}
