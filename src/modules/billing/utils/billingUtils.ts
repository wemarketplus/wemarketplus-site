import { formatDate } from '@/shared/utils/dateFormatter';
import { Tier, SubscriptionStatus, normalizeTier } from '@/shared/types';
import type { Product, Tier as TierType } from '@/shared/types';
import type { SubscriptionRecord, SubscriptionView } from '../types/billingTypes';

// Coerces the backend plan info to a known Tier for the UI. Prefers the
// catalog-resolved `tier` the backend now ships; the substring heuristic on
// `plan` is only a fallback for rows the catalog cannot resolve (legacy or
// unconfigured price ids, where `plan` is a raw Stripe price id).
export function toTier(plan: string, tier?: string): TierType {
  const resolved = normalizeTier(tier);
  if (resolved) return resolved;
  const p = plan.toLowerCase();
  if (p.includes('max')) return Tier.Max;
  if (p.includes('gold')) return Tier.Gold;
  return Tier.Pro;
}

// Product/org name come from auth context as the fallback for records the
// backend could not resolve against the catalog. Pure mapper — kept in utils/.
export function toSubscriptionView(
  record: SubscriptionRecord,
  product: Product,
  organizationName: string,
): SubscriptionView {
  return {
    product: record.product ?? product,
    plan: toTier(record.plan, record.tier),
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

// Formats a Stripe minor-unit amount (cents) as a localized currency string,
// e.g. (30000, 'usd') -> "$300.00". Used by the plan-change proration dialog.
export const formatMinorAmount = (
  minorAmount: number,
  currency: string,
): string =>
  new Intl.NumberFormat(undefined, {
    style: 'currency',
    currency: currency.toUpperCase(),
  }).format(minorAmount / 100);

// Formats a Unix timestamp (seconds) as a friendly date — the "effective on"
// line in the proration dialog.
export const formatUnixDate = (unixSeconds: number): string =>
  formatDate(new Date(unixSeconds * 1000).toISOString(), 'PPP');
