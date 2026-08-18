import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import type { AppNotification } from '@/shared/types';
import { useListNotificationsQuery } from '../api/notificationsApi';
import { mapNotification } from '../utils/notificationsUtils';

/**
 * The notification list, filtered by the drawer's current tab.
 *
 * MEMOISATION IS LOAD-BEARING HERE, not tidiness. `list` used to be built outside
 * `useMemo`:
 *
 *   const list = data ? data.data.map(mapNotification) : [];
 *
 * which produced a NEW array on every render. Both memos below depend on `list`, so
 * their dependency changed every render too — they recomputed every time, and every
 * consumer received fresh `filtered` / `list` references and re-rendered in turn.
 *
 * That is the mechanism behind the "leaving the notifications panel open can freeze
 * rendering" report. On its own the wasted work is small; combined with the SSE feed
 * it compounds, because `useNotificationsStream` dispatches
 * `invalidateTags([List])` for EVERY incoming notification, and each invalidation
 * refetches this query for every mounted consumer — the drawer and the page both use
 * this hook. A burst of notifications with the panel open therefore drove a
 * refetch-plus-full-re-render loop with nothing damping it.
 *
 * Keeping the `data.data` reference as the dependency is what fixes it: RTK Query
 * hands back the same array identity until the data actually changes, so a re-render
 * that changed nothing now recomputes nothing.
 */
export function useNotifications() {
  const { data, isLoading } = useListNotificationsQuery();
  const filter = useAppSelector((s) => s.notifications.filter);

  const rows = data?.data;

  // Show the tenant's real notifications, or an empty list when there are none.
  const list = useMemo<readonly AppNotification[]>(
    () => (rows ? rows.map(mapNotification) : []),
    [rows],
  );

  const filtered = useMemo(() => {
    if (filter === 'all') return list;
    if (filter === 'unread') return list.filter((n) => !n.read);
    return list.filter((n) => n.category === filter);
  }, [list, filter]);

  const unreadCount = useMemo(
    () => list.filter((n) => !n.read).length,
    [list],
  );

  return {
    list,
    filtered,
    unreadCount,
    isLoading,
    isUsingFixture: false,
  };
}
