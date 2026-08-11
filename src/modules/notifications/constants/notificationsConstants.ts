import { Product, Tier } from '@/shared/types';
import { AlertTriangle, Bell, CheckCheck, MessageSquare } from 'lucide-react';
import type { ComponentType } from 'react';
import type { AppNotification } from '@/shared/types';
import type { NotificationFilter } from '../types/notificationsTypes';

export const NOTIFICATIONS_TAGS = {
  List: 'Notifications.List',
  Preferences: 'Notifications.Preferences',
} as const;

// Human-readable labels for the configurable notification types surfaced in the
// preference center. Mirrors CONFIGURABLE_NOTIFICATION_TYPES on the backend.
export const NOTIFICATION_TYPE_LABELS: Record<
  string,
  { label: string; description: string }
> = {
  'prospect.assigned': {
    label: 'Prospect assigned to me',
    description: 'When a prospect is assigned to you.',
  },
  'task.assigned': {
    label: 'Task assigned to me',
    description: 'When a task is created for or reassigned to you.',
  },
};

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

/**
 * Tier required to configure ALERT ROUTING (who is notified, over which
 * channel), per product.
 *
 * Mirrors the backend's per-product override of the `alert_settings` feature
 * rank (FEATURE_MIN_RANK_BY_PRODUCT in plan-catalog.ts): HospiceLink sells this
 * as base functionality — its product guide presents "choose who gets a text or
 * email alert" alongside the team roster — while CommunityLink sells it in the
 * Max admin bundle.
 *
 * Change one side, change both, or the tab appears for a tenant whose API calls
 * will 402.
 */
export const ALERT_ROUTING_MIN_TIER = {
  [Product.HospiceLink]: Tier.Pro,
  [Product.CommunityLink]: Tier.Max,
} as const satisfies Partial<Record<Product, Tier>>;
