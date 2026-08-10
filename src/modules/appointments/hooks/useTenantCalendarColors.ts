import { useMemo } from 'react';
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
 * `enabled` exists because this is only needed by the "All users" view: a
 * personal calendar is one person's rows, where a per-owner colour carries no
 * information. Skipping the request there keeps the common case at zero extra
 * network cost.
 *
 * Users who have not chosen are simply absent from the map, which is exactly
 * what `calendarColorFor(id, undefined)` wants — it derives their colour from
 * the id, as it always has.
 */
export function useTenantCalendarColors(enabled: boolean): CalendarColorMap {
  const { data } = useListCalendarColorsQuery(undefined, { skip: !enabled });

  return useMemo(() => {
    if (!data) return EMPTY;
    return data.reduce<Record<string, string>>((acc, entry) => {
      if (entry.calendarColor) acc[entry.userId] = entry.calendarColor;
      return acc;
    }, {});
  }, [data]);
}
