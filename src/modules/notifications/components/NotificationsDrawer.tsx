import { useEffect } from 'react';
import { CheckCheck, X } from 'lucide-react';
import { useAppDispatch, useAppSelector } from '@/app/hooks';
import { Button } from '@/shared/ui/core';
import { closeDrawer, setFilter } from '../store/notificationsSlice';
import { useMarkAllReadMutation } from '../api/notificationsApi';
import { useNotifications } from '../hooks/useNotifications';
import { NotificationsList } from './NotificationsList';
import { cn } from '@/shared/utils/cn';

const FILTERS: ReadonlyArray<{ value: 'all' | 'unread'; label: string }> = [
  { value: 'all', label: 'All' },
  { value: 'unread', label: 'Unread' },
];

export function NotificationsDrawer() {
  const dispatch = useAppDispatch();
  const open = useAppSelector((s) => s.notifications.drawerOpen);
  const filter = useAppSelector((s) => s.notifications.filter);
  const { filtered, unreadCount } = useNotifications();
  const [markAllRead, markAllState] = useMarkAllReadMutation();

  // Close on Escape.
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') dispatch(closeDrawer());
    };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [dispatch, open]);

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
        onClick={() => dispatch(closeDrawer())}
        className="absolute inset-0 bg-black/60 backdrop-blur-sm"
      />
      <aside
        className={cn(
          'absolute right-0 top-0 flex h-full w-full max-w-[420px] flex-col border-l border-white/[0.08] bg-bg shadow-2xl transition-transform duration-300',
          open ? 'translate-x-0' : 'translate-x-full',
        )}
        role="dialog"
        aria-label="Notifications"
      >
        <header className="flex items-center justify-between border-b border-white/[0.06] px-4 py-4">
          <div>
            <h2 className="text-base font-semibold text-foreground">Notifications</h2>
            <p className="text-[11px] uppercase tracking-[0.1em] text-muted-soft">
              {unreadCount} unread
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              disabled={markAllState.isLoading || unreadCount === 0}
              onClick={() => markAllRead()}
              aria-label="Mark all read"
            >
              <CheckCheck className="h-4 w-4" />
              <span className="hidden sm:inline">Mark all read</span>
            </Button>
            <Button
              variant="ghost"
              size="icon"
              aria-label="Close"
              onClick={() => dispatch(closeDrawer())}
            >
              <X className="h-4 w-4" />
            </Button>
          </div>
        </header>

        <nav className="flex gap-1.5 border-b border-white/[0.06] px-4 py-3">
          {FILTERS.map((f) => (
            <button
              key={f.value}
              type="button"
              onClick={() => dispatch(setFilter(f.value))}
              className={cn(
                'rounded-pill border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
                filter === f.value
                  ? 'border-primary/40 bg-primary/15 text-primary'
                  : 'border-white/[0.08] text-muted hover:border-white/20 hover:text-foreground',
              )}
            >
              {f.label}
            </button>
          ))}
        </nav>

        <div className="flex-1 overflow-y-auto">
          <NotificationsList items={filtered} />
        </div>
      </aside>
    </div>
  );
}
