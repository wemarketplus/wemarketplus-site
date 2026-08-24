import { PAGE_TITLE } from '@/shared/ui/core/typography';
import { useMemo, useState } from 'react';
import { CheckCheck } from 'lucide-react';
import { useActiveEntitlement } from '@/modules/access';
import { AlertRoutingPanel } from '@/modules/cl-admin-settings';
import { ADMIN_ONLY, useRole } from '@/shared/rbac';
import { tierIncludes } from '@/shared/types';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { useNotifications } from '../hooks/useNotifications';
import { useNotificationActivate } from '../hooks/useNotificationActivate';
import { useNotificationsControls } from '../hooks/useNotificationsControls';
import { NotificationsList } from '../components/NotificationsList';
import { NotificationsPreferences } from '../components/NotificationsPreferences';
import {
  ALERT_ROUTING_MIN_TIER,
  NOTIFICATIONS_PAGE_TABS,
} from '../constants/notificationsConstants';
import { cn } from '@/shared/utils/cn';

type Section = 'feed' | 'preferences' | 'alerts';

const FEED_TAB = { value: 'feed', label: 'Feed' } as const;
const PREFERENCES_TAB = { value: 'preferences', label: 'Preferences' } as const;

/**
 * Admin-only routing tab. Named "Team alerts" to distinguish it from
 * "Preferences", which is the caller's OWN in-app toggles — the two are easy to
 * confuse and control very different things.
 */
const ALERTS_TAB = { value: 'alerts', label: 'Team alerts' } as const;

const SECTION_BLURB: Record<Section, string> = {
  feed: '',
  preferences: 'Choose which events notify you in-app',
  alerts: 'Choose who is notified for each event, and whether by email or SMS',
};

export function NotificationsPage() {
  const { filtered, unreadCount } = useNotifications();
  const { filter, changeFilter, markAllRead, isMarkingAll } = useNotificationsControls();
  const activate = useNotificationActivate();
  const [section, setSection] = useState<Section>('feed');
  const { isAny } = useRole();
  const { product, tier, isResolved } = useActiveEntitlement();

  /**
   * The alert-routing tab is shown only when the caller could actually use it:
   * an admin, on a plan that includes it. Gating here rather than letting the
   * request 402 matters because baseQueryWithReauth turns a 402 into a hard
   * redirect to /billing — an admin clicking a tab would be thrown off the page.
   */
  const canRouteAlerts =
    isResolved &&
    isAny(ADMIN_ONLY) &&
    tierIncludes(product, tier, ALERT_ROUTING_MIN_TIER[product]);

  const sections = useMemo(
    () =>
      canRouteAlerts
        ? [FEED_TAB, PREFERENCES_TAB, ALERTS_TAB]
        : [FEED_TAB, PREFERENCES_TAB],
    [canRouteAlerts],
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className={PAGE_TITLE}>Notifications</h1>
          <p className="text-sm text-muted">
            {section === 'feed'
              ? `${unreadCount} unread · everything that's happened across your CRM`
              : SECTION_BLURB[section]}
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
        {sections.map((s) => (
          <button
            key={s.value}
            type="button"
            onClick={() => setSection(s.value)}
            className={cn(
              'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-label transition-colors',
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
                    'rounded-pill border px-3 py-1.5 text-[11px] font-semibold uppercase tracking-label transition-colors',
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
      ) : section === 'preferences' ? (
        <Card>
          <CardContent className="px-0 py-0">
            <NotificationsPreferences />
          </CardContent>
        </Card>
      ) : (
        /*
          The HospiceLink product guide tells an Office Manager to "Click
          Notifications to control who gets a text or email alert, and for what".
          This tab is that control. It renders the SAME component CommunityLink
          shows on its own Alert settings page — one implementation, two frames.
        */
        <AlertRoutingPanel />
      )}
    </div>
  );
}
