import { Link } from 'react-router-dom';
import { formatRelative } from '@/shared/utils/dateFormatter';
import { CATEGORY_ICON, CATEGORY_TONE_CLASS } from '../constants/notificationsConstants';
import { cn } from '@/shared/utils/cn';
import type { NotificationsListProps } from '../types/notificationsTypes';

export function NotificationsList({ items, emptyState, onActivate }: NotificationsListProps) {
  if (items.length === 0) {
    return (
      <div className="rounded-md border border-border/[0.06] bg-foreground/[0.02] p-8 text-center text-sm text-muted">
        {emptyState ?? "You're all caught up."}
      </div>
    );
  }

  return (
    <ul className="divide-y divide-white/[0.06]">
      {items.map((n) => {
        const Icon = CATEGORY_ICON[n.category];
        const Body = (
          <div
            className={cn(
              'flex gap-3 px-4 py-3 transition-colors hover:bg-foreground/[0.03]',
              !n.read && 'bg-foreground/[0.02]',
            )}
          >
            <div className={cn('mt-0.5 shrink-0', CATEGORY_TONE_CLASS[n.category])}>
              <Icon className="h-4 w-4" />
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-3">
                <p className="truncate text-sm font-semibold text-foreground">
                  {n.title}
                </p>
                <span className="shrink-0 text-[10px] uppercase tracking-label text-muted-soft">
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
              <Link to={n.href} onClick={() => onActivate?.(n)} className="block">
                {Body}
              </Link>
            </li>
          );
        }

        return (
          <li key={n.id}>
            <button
              type="button"
              onClick={() => onActivate?.(n)}
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
