import { Bell } from 'lucide-react';
import { useAppDispatch } from '@/app/hooks';
import { Button } from '@/shared/ui/core';
import { toggleDrawer } from '../store/notificationsSlice';
import { useNotifications } from '../hooks/useNotifications';

// Topbar bell. Counts unread notifications and animates the dot when there
// are any unseen items.
export function NotificationsBell() {
  const dispatch = useAppDispatch();
  const { unreadCount } = useNotifications();
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
