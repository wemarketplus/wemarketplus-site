import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { NOTIFICATIONS_FIXTURE } from '@/shared/fixtures';
import type { AppNotification } from '@/shared/types';
import { useListNotificationsQuery } from '../api/notificationsApi';
import { mapNotification } from '../utils/notificationsUtils';

export function useNotifications() {
  const { data, isLoading } = useListNotificationsQuery();
  const filter = useAppSelector((s) => s.notifications.filter);

  // Fixture fallback until the tenant has live notifications. Once the backend
  // returns a page (even an empty one), we trust it.
  const list: readonly AppNotification[] = data
    ? data.data.map(mapNotification)
    : NOTIFICATIONS_FIXTURE;

  const filtered = useMemo(() => {
    if (filter === 'all') return list;
    if (filter === 'unread') return list.filter((n) => !n.read);
    return list.filter((n) => n.category === filter);
  }, [list, filter]);

  const unreadCount = useMemo(() => list.filter((n) => !n.read).length, [list]);

  return {
    list,
    filtered,
    unreadCount,
    isLoading,
    isUsingFixture: !data,
  };
}
