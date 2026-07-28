import { useState } from 'react';
import { CheckCheck } from 'lucide-react';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { useNotifications } from '../hooks/useNotifications';
import { useNotificationActivate } from '../hooks/useNotificationActivate';
import { useNotificationsControls } from '../hooks/useNotificationsControls';
import { NotificationsList } from '../components/NotificationsList';
import { NotificationsPreferences } from '../components/NotificationsPreferences';
import { NOTIFICATIONS_PAGE_TABS } from '../constants/notificationsConstants';
import { cn } from '@/shared/utils/cn';

type Section = 'feed' | 'preferences';

const SECTIONS: ReadonlyArray<{ value: Section; label: string }> = [
  { value: 'feed', label: 'Feed' },
  { value: 'preferences', label: 'Preferences' },
];

export function NotificationsPage() {
  const { filtered, unreadCount } = useNotifications();
  const { filter, changeFilter, markAllRead, isMarkingAll } = useNotificationsControls();
  const activate = useNotificationActivate();
  const [section, setSection] = useState<Section>('feed');

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="font-display text-3xl text-foreground">Notifications</h1>
          <p className="text-sm text-muted">
            {section === 'feed'
              ? `${unreadCount} unread · everything that's happened across your CRM`
              : 'Choose which events notify you in-app'}
          </p>
        </div>
        {section === 'feed' && (
          <Button
            variant="secondary"
            disabled={isMarkingAll || unreadCount === 0}
            onClick={markAllRead}
          >
            <CheckCheck className="h-4 w-4" /> Mark all as read
          </Button>
        )}
      </div>

      <nav className="flex flex-wrap gap-1.5">
        {SECTIONS.map((s) => (
          <button
            key={s.value}
            type="button"
            onClick={() => setSection(s.value)}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
              section === s.value
                ? 'border-primary/40 bg-primary/15 text-primary'
                : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
            )}
          >
            {s.label}
          </button>
        ))}
      </nav>

      {section === 'feed' ? (
        <Card>
          <CardContent className="space-y-4 px-0 pt-4 pb-0">
            <nav className="flex flex-wrap gap-1.5 px-4">
              {NOTIFICATIONS_PAGE_TABS.map((t) => (
                <button
                  key={t.value}
                  type="button"
                  onClick={() => changeFilter(t.value)}
                  className={cn(
                    'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-[0.08em] transition-colors',
                    filter === t.value
                      ? 'border-primary/40 bg-primary/15 text-primary'
                      : 'border-border/[0.08] text-muted hover:border-border/20 hover:text-foreground',
                  )}
                >
                  {t.label}
                </button>
              ))}
            </nav>
            <div className="border-t border-border/[0.06]">
              <NotificationsList items={filtered} onActivate={activate} />
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="px-0 py-0">
            <NotificationsPreferences />
          </CardContent>
        </Card>
      )}
    </div>
  );
}
