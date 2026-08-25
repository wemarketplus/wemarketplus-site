import { Bell } from 'lucide-react';
import { useAppDispatch } from '@/app/hooks';
import { Button } from '@/shared/ui/core';
import { HEADER_CONTROL_BASE } from '@/shared/ui/core/controlStyles';
import { cn } from '@/shared/utils/cn';
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
      // HEADER_CONTROL_BASE gives the bell the same hairline and surface as the
      // search pill, the switcher and the profile chip. As a bare `ghost` it was
      // the only control in the row with no visible hit area, so a row of four
      // bordered chips had an unbordered glyph sitting in the middle of it — the
      // "notification icon is not visually balanced" report. `size="icon"`
      // already supplies the 36px square, so the height is not restated here.
      className={cn(HEADER_CONTROL_BASE, 'relative')}
    >
      <Bell className="h-4 w-4" />
      {unreadCount > 0 && (
        /*
         * The badge sits on the button's TOP-RIGHT CORNER, not inside it.
         *
         * It was `right-1 top-1.5`, which put a 16px pill at x 16–32 / y 6–22
         * inside a 36px box whose 16px glyph occupies 10–26 on both axes — so
         * the badge covered the bell's entire top-right quadrant and, at two
         * digits, most of the glyph. The control that is supposed to say
         * "notifications" was legible as a green blob and nothing else.
         *
         * `-top-0.5 -right-0.5` with a ring in the header's own background
         * colour is the standard notification-dot treatment: it reads as
         * attached to the bell while leaving the glyph itself unobscured.
         */
        <span className="absolute -right-0.5 -top-0.5 flex h-[17px] min-w-[17px] items-center justify-center rounded-full bg-primary px-1 text-[10px] font-bold leading-none text-primary-foreground ring-2 ring-bg">
          {unreadCount > 9 ? '9+' : unreadCount}
        </span>
      )}
    </Button>
  );
}
