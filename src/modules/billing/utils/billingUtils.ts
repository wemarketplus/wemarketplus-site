import { formatDate } from '@/shared/utils/dateFormatter';
import { Tier, SubscriptionStatus } from '@/shared/types';
import type { Product, Tier as TierType } from '@/shared/types';
import type { SubscriptionRecord, SubscriptionView } from '../types/billingTypes';

// Backend `plan` is a free-form string; coerce it to a known Tier for the UI.
export function toTier(plan: string): TierType {
  const p = plan.toLowerCase();
  if (p.includes('max')) return Tier.Max;
  if (p.includes('gold')) return Tier.Gold;
  return Tier.Pro;
}

// The backend subscription record has no product/org-name fields, so the caller
// supplies those (derived from auth). Pure mapper — kept in utils/.
export function toSubscriptionView(
  record: SubscriptionRecord,
  product: Product,
  organizationName: string,
): SubscriptionView {
  return {
    product,
    plan: toTier(record.plan),
    status: record.status,
    // The page always renders a renewal date; fall back to created date.
    currentPeriodEnd: record.currentPeriodEnd ?? record.createdAt,
    organizationName,
  };
}

export const statusLabel = (status: SubscriptionStatus): string => {
  switch (status) {
    case SubscriptionStatus.Active:
      return 'Active';
    case SubscriptionStatus.Trialing:
      return 'Trial';
    case SubscriptionStatus.PastDue:
      return 'Past due';
    case SubscriptionStatus.Suspended:
      return 'Suspended';
    case SubscriptionStatus.Canceled:
      return 'Canceled';
  }
};

export const statusToneClass = (status: SubscriptionStatus): string => {
  switch (status) {
    case SubscriptionStatus.Active:
    case SubscriptionStatus.Trialing:
      return 'border-success/30 bg-success/10 text-success';
    case SubscriptionStatus.PastDue:
      return 'border-warning/30 bg-warning/10 text-warning';
    case SubscriptionStatus.Suspended:
    case SubscriptionStatus.Canceled:
      return 'border-destructive/30 bg-destructive/10 text-destructive';
  }
};

export const formatPeriodEnd = (iso: string): string => formatDate(iso, 'PPP');
