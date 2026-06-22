import { AlertTriangle, Bell, CheckCheck, MessageSquare } from 'lucide-react';
import type { ComponentType } from 'react';
import type { AppNotification } from '@/shared/types';
import type { NotificationFilter } from '../types/notificationsTypes';

export const NOTIFICATIONS_TAGS = {
  List: 'Notifications.List',
} as const;

type NotificationCategory = AppNotification['category'];

// Icon shown per notification category (config — references UI components, so
// it lives in constants, not the framework-agnostic utils).
export const CATEGORY_ICON: Record<
  NotificationCategory,
  ComponentType<{ className?: string }>
> = {
  alert: AlertTriangle,
  task: CheckCheck,
  mention: MessageSquare,
  system: Bell,
};

// Text-color class per notification category.
export const CATEGORY_TONE_CLASS: Record<NotificationCategory, string> = {
  alert: 'text-warning',
  task: 'text-primary',
  mention: 'text-azure',
  system: 'text-muted',
};

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
