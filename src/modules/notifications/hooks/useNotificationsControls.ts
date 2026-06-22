import { useCallback } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { useMarkAllReadMutation } from '../api/notificationsApi';
import { setFilter } from '../store/notificationsSlice';
import type { NotificationFilter } from '../types/notificationsTypes';

// Orchestrates the notifications filter + mark-all-read controls shared by the
// page and the drawer, so those views stay presentational.
export function useNotificationsControls() {
  const dispatch = useAppDispatch();
  const filter = useAppSelector((s) => s.notifications.filter);
  const [markAllRead, markAllState] = useMarkAllReadMutation();

  const changeFilter = useCallback(
    (next: NotificationFilter) => dispatch(setFilter(next)),
    [dispatch],
  );

  return {
    filter,
    changeFilter,
    markAllRead: () => markAllRead(),
    isMarkingAll: markAllState.isLoading,
  };
}
