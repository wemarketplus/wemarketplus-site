import { SubscriptionStatus } from '@/shared/types';
import {
  SUBSCRIPTION_ALERTS,
  SUBSCRIPTION_ALERT_DESCRIPTIONS,
} from '../constants/billingConstants';
import { formatPeriodEnd } from '../utils/billingUtils';
import type { SubscriptionAlert, SubscriptionView } from '../types/billingTypes';

// Resolves the alert (if any) the billing page should surface for a
// subscription. Looks up the static config from constants, then fills the
// description — fixed copy for most statuses, date-derived for Canceled.
// Returns null for healthy states (active / trialing).
export function useSubscriptionAlert(
  data: SubscriptionView,
): SubscriptionAlert | null {
  const config = SUBSCRIPTION_ALERTS[data.status];
  if (!config) return null;

  const description =
    data.status === SubscriptionStatus.Canceled
      ? `You can reactivate any time before ${
          data.scheduledDeleteAt
            ? formatPeriodEnd(data.scheduledDeleteAt)
            : 'your data is purged'
        }.`
      : (SUBSCRIPTION_ALERT_DESCRIPTIONS[data.status] ?? '');

  return { ...config, description };
}
