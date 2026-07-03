import { Bell } from 'lucide-react';
import { useAppDispatch } from '@/app/hooks';
import { Button } from '@/shared/ui/core';
import { toggleDrawer } from '../store/notificationsSlice';
import { useUnreadCountQuery } from '../api/notificationsApi';

// Topbar bell. Uses the authoritative /notifications/unread-count for the badge
// (kept fresh by the realtime stream, which invalidates the List tag). Falls
// back to 0 while loading or if the tenant has no notifications yet.
export function NotificationsBell() {
  const dispatch = useAppDispatch();
  const { data: unreadCount = 0 } = useUnreadCountQuery();
  return (
    <Button
      variant="ghost"
      size="icon"
      aria-label={`Notifications${unreadCount ? ` (${unreadCount} unread)` : ''}`}
      onClick={() => dispatch(toggleDrawer())}
      className="relative"
    >
      <Bell className="h-4 w-4" />
      {unreadCount > 0 && (
        <span className="absolute right-1 top-1.5 flex h-4 min-w-[16px] items-center justify-center rounded-full bg-primary px-1 text-[10px] font-bold text-primary-foreground">
          {unreadCount > 9 ? '9+' : unreadCount}
        </span>
      )}
    </Button>
  );
}
