import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { CheckCheck, X } from 'lucide-react';
import { Button } from '@/shared/ui/core';
import { useNotifications } from '../hooks/useNotifications';
import { useNotificationActivate } from '../hooks/useNotificationActivate';
import { useNotificationsControls } from '../hooks/useNotificationsControls';
import { useNotificationsDrawer } from '../hooks/useNotificationsDrawer';
import { NotificationsList } from './NotificationsList';
import { NOTIFICATIONS_DRAWER_FILTERS } from '../constants/notificationsConstants';
import { useRegisterOverlay } from '@/shared/ui/feedback';
import { cn } from '@/shared/utils/cn';

export function NotificationsDrawer() {
  const { open, close } = useNotificationsDrawer();
  // Same rule as the modals: no topbar behind an open popup surface. This one
  // stays mounted and fades, so the flag follows `open`, not mount state.
  useRegisterOverlay(open);
  const { filtered, unreadCount } = useNotifications();
  const { filter, changeFilter, markAllRead, isMarkingAll } = useNotificationsControls();
  const activate = useNotificationActivate();

  return (
    <div
      className={cn(
        'fixed inset-0 z-50 transition-opacity duration-200',
        open ? 'pointer-events-auto opacity-100' : 'pointer-events-none opacity-0',
      )}
      aria-hidden={!open}
    >
      <button
        type="button"
        aria-label="Close notifications"
        onClick={close}
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
      />
      <aside
        className={cn(
          'absolute right-0 top-0 flex h-full w-full max-w-[420px] flex-col border-l border-border/[0.08] bg-bg shadow-2xl transition-transform duration-300',
          open ? 'translate-x-0' : 'translate-x-full',
        )}
        role="dialog"
        aria-label="Notifications"
      >
        <header className="flex items-center justify-between border-b border-border/[0.06] px-4 py-4">
          <div>
            <h2 className={SECTION_TITLE}>Notifications</h2>
            <p className="text-[11px] uppercase tracking-label text-muted-soft">
              {unreadCount} unread
            </p>
          </div>
          <div className="flex items-center gap-2">
            {/*
              `secondary`, not `ghost` — and this is the same defect Button.tsx's
              own doc describes for the quiet variants: `ghost` is
              `bg-transparent text-muted`, so this had NO boundary of any kind.
              Measured live on the drawer's white surface: #6a726e text, `rgba(0,
              0, 0, 0)` background, `border-width: 0px`. The label alone clears AA
              as text (4.95:1), which is exactly why this reads as low-visibility
              rather than as broken — a control needs 3:1 on its BOUNDARY (WCAG
              1.4.11), and it had no boundary to measure. Sitting immediately left
              of the `ghost size="icon"` Close button, the bulk state change and
              the dismiss were rendered at identical weight.

              `secondary` is the app's existing "visible but not shouting"
              variant: `border-border/50` (3.30:1 on white — the doc records 50%
              as the lowest alpha that clears the floor) over `bg-surface-raised`.
              It is also what the full Notifications PAGE already uses for this
              same action, so one action now looks like one action on both
              surfaces. `size="sm"` is kept for the drawer's 36px header band
              where the page uses the default `md`.

              Close stays `ghost` — that IS the right variant for a dismiss, and
              keeping it is what re-establishes the difference in weight between
              the two.
            */}
            <Button
              variant="secondary"
              size="sm"
              disabled={isMarkingAll || unreadCount === 0}
              onClick={markAllRead}
              aria-label="Mark all read"
            >
              <CheckCheck className="h-4 w-4" />
              <span className="hidden sm:inline">Mark all read</span>
            </Button>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Close"
              onClick={close}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </header>

        <nav className="flex gap-1.5 border-b border-border/[0.06] px-4 py-3">
          {NOTIFICATIONS_DRAWER_FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              onClick={() => changeFilter(f.value)}
              className={cn(
                'rounded-pill border px-3 py-1 text-[11px] font-semibold uppercase tracking-label transition-colors',
                filter === f.value
                  ? 'border-primary/40 bg-primary/15 text-primary'
                  : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
              )}
            >
              {f.label}
            </button>
          ))}
        </nav>

        <div className="flex-1 overflow-y-auto">
          <NotificationsList items={filtered} onActivate={activate} />
        </div>
      </aside>
    </div>
  );
}
