import { useCallback, useEffect } from 'react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { closeDrawer } from '../store/notificationsSlice';

// Drawer-specific orchestration: open state, close action, and the Escape-to-
// close side effect. Keeps NotificationsDrawer presentational.
export function useNotificationsDrawer() {
  const dispatch = useAppDispatch();
  const open = useAppSelector((s) => s.notifications.drawerOpen);

  const close = useCallback(() => dispatch(closeDrawer()), [dispatch]);

  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') close();
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [open, close]);

  return { open, close };
}
