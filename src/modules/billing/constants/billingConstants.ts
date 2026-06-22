import { AlertTriangle, RotateCcw } from 'lucide-react';
import { SubscriptionStatus } from '@/shared/types';
import type { AlertTone, SubscriptionAlertConfig } from '../types/billingTypes';

export const BILLING_TAGS = {
  Subscription: 'Billing.Subscription',
} as const;

// Ring/background/text classes per alert tone (analogous to prospects STATUS_TONE).
export const ALERT_TONE_CLASS: Record<AlertTone, string> = {
  warning: 'bg-warning/15 text-warning ring-warning/30',
  destructive: 'bg-destructive/15 text-destructive ring-destructive/30',
};

// Static alert config per subscription status that needs attention. The dynamic
// description is derived in useSubscriptionAlert. Healthy statuses (active /
// trialing) intentionally have no entry → no alert is shown.
export const SUBSCRIPTION_ALERTS: Partial<
  Record<SubscriptionStatus, SubscriptionAlertConfig>
> = {
  [SubscriptionStatus.PastDue]: {
    icon: AlertTriangle,
    tone: 'warning',
    title: 'Your last payment failed',
    actionLabel: 'Update payment method',
  },
  [SubscriptionStatus.Suspended]: {
    icon: AlertTriangle,
    tone: 'destructive',
    title: 'Workspace temporarily suspended',
    actionLabel: 'Restore access now',
  },
  [SubscriptionStatus.Canceled]: {
    icon: RotateCcw,
    tone: 'destructive',
    title: 'Subscription canceled',
    actionLabel: 'Reactivate',
  },
};

// Static descriptions for statuses whose copy is fixed (not date-derived).
export const SUBSCRIPTION_ALERT_DESCRIPTIONS: Partial<
  Record<SubscriptionStatus, string>
> = {
  [SubscriptionStatus.PastDue]: 'Update your card to keep your workspace active.',
  [SubscriptionStatus.Suspended]:
    'Restore access by settling your balance — no data has been deleted.',
};

// Seat count that represents an unlimited plan in the catalog.
export const UNLIMITED_SEATS = 999;
