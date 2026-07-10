import { useCallback } from 'react';
import { useAppDispatch } from '@/app/hooks';
import type { AppNotification } from '@/shared/types';
import { closeDrawer } from '../store/notificationsSlice';
import { useMarkReadMutation } from '../api/notificationsApi';

// Orchestrates activating a notification row: marks it read (if unread) and
// closes the drawer when the notification links somewhere. Keeps the mutation
// + dispatch out of the presentational list component.
export function useNotificationActivate() {
  const dispatch = useAppDispatch();
  const [markRead] = useMarkReadMutation();

  return useCallback(
    (notification: AppNotification) => {
      if (!notification.read) markRead(notification.id);
      if (notification.href) dispatch(closeDrawer());
    },
    [markRead, dispatch],
  );
}
