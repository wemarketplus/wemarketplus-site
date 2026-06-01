import { Link } from 'react-router-dom';
import { useAppDispatch } from '@/app/hooks';
import { closeDrawer } from '../store/notificationsSlice';
import { useMarkReadMutation } from '../api/notificationsApi';
import { formatRelative } from '@/shared/utils/dateFormatter';
import { categoryIcon, categoryToneClass } from '../utils/notificationsUtils';
import { cn } from '@/shared/utils/cn';
import type { AppNotification } from '@/shared/types';

interface NotificationsListProps {
  items: readonly AppNotification[];
  emptyState?: React.ReactNode;
}

export function NotificationsList({ items, emptyState }: NotificationsListProps) {
  const dispatch = useAppDispatch();
  const [markRead] = useMarkReadMutation();

  if (items.length === 0) {
    return (
      <div className="rounded-md border border-white/[0.06] bg-white/[0.02] p-8 text-center text-sm text-muted">
        {emptyState ?? "You're all caught up."}
      </div>
    );
  }

  return (
    <ul className="divide-y divide-white/[0.06]">
      {items.map((n) => {
        const Icon = categoryIcon(n.category);
        const Body = (
          <div
            className={cn(
              'flex gap-3 px-4 py-3 transition-colors hover:bg-white/[0.03]',
              !n.read && 'bg-white/[0.02]',
            )}
          >
            <div className={cn('mt-0.5 shrink-0', categoryToneClass(n.category))}>
              <Icon className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-3">
                <p className="truncate text-sm font-semibold text-foreground">
                  {n.title}
                </p>
                <span className="shrink-0 text-[10px] uppercase tracking-[0.1em] text-muted-soft">
                  {formatRelative(n.createdAt)}
                </span>
              </div>
              <p className="mt-0.5 line-clamp-2 text-xs text-muted">{n.body}</p>
            </div>
            {!n.read && (
              <span
                aria-label="Unread"
                className="mt-1.5 h-2 w-2 shrink-0 rounded-full bg-primary"
              />
            )}
          </div>
        );

        if (n.href) {
          return (
            <li key={n.id}>
              <Link
                to={n.href}
                onClick={() => {
                  if (!n.read) markRead(n.id);
                  dispatch(closeDrawer());
                }}
                className="block"
              >
                {Body}
              </Link>
            </li>
          );
        }

        return (
          <li key={n.id}>
            <button
              type="button"
              onClick={() => !n.read && markRead(n.id)}
              className="block w-full text-left"
            >
              {Body}
            </button>
          </li>
        );
      })}
    </ul>
  );
}
