import type { NotificationFilter } from '../types/notificationsTypes';

export const NOTIFICATIONS_TAGS = {
  List: 'Notifications.List',
} as const;

// Filter chips shown in the slide-over drawer.
export const NOTIFICATIONS_DRAWER_FILTERS: ReadonlyArray<{
  value: 'all' | 'unread';
  label: string;
}> = [
  { value: 'all', label: 'All' },
  { value: 'unread', label: 'Unread' },
];

// Tabs shown on the full notifications page.
export const NOTIFICATIONS_PAGE_TABS: ReadonlyArray<{
  value: NotificationFilter;
  label: string;
}> = [
  { value: 'all', label: 'All' },
  { value: 'unread', label: 'Unread' },
  { value: 'alert', label: 'Alerts' },
  { value: 'task', label: 'Tasks' },
  { value: 'mention', label: 'Mentions' },
  { value: 'system', label: 'System' },
];
