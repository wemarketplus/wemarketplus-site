import { useMemo } from 'react';
import { useAppSelector } from '@/app/hooks';
import { NOTIFICATIONS_FIXTURE } from '@/shared/fixtures';
import type { AppNotification } from '@/shared/types';
import { useListNotificationsQuery } from '../api/notificationsApi';

// Same fixture-fallback pattern as billing — when backend ships
// /notifications, the fixture branch becomes dead and can be removed.
export function useNotifications() {
  const { data, isLoading } = useListNotificationsQuery();
  const filter = useAppSelector((s) => s.notifications.filter);

  const list: readonly AppNotification[] = data ?? NOTIFICATIONS_FIXTURE;

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
    isUsingFixture: !data,
  };
}
