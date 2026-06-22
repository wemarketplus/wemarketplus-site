// Product/tier system mirrors the site, where one auth account routes to one
// of two CRM products at different feature tiers. Today the backend does not
// expose these on /auth/me; we default to HospiceLink Pro until it does. When
// the backend ships the fields, wire them in `@/modules/auth/types/authTypes`
// and the navigation filter in `@/shared/config/navigationConfig`.

export const Product = {
  HospiceLink: 'hospicelink',
  CommunityLink: 'communitylink',
} as const;
export type Product = (typeof Product)[keyof typeof Product];

export const PRODUCT_LABELS: Record<Product, string> = {
  [Product.HospiceLink]: 'HospiceLink',
  [Product.CommunityLink]: 'CommunityLink',
};

export const Tier = {
  Pro: 'pro',
  Gold: 'gold',
  Max: 'max',
} as const;
export type Tier = (typeof Tier)[keyof typeof Tier];

export const TIER_LABELS: Record<Tier, string> = {
  [Tier.Pro]: 'Pro',
  [Tier.Gold]: 'Gold',
  [Tier.Max]: 'Max',
};

// Tier rank — higher numbers unlock more features.
const TIER_RANK: Record<Tier, number> = {
  [Tier.Pro]: 1,
  [Tier.Max]: 2,
  [Tier.Gold]: 3,
};

export const tierIncludes = (current: Tier, required: Tier): boolean =>
  TIER_RANK[current] >= TIER_RANK[required];

// Subscription status mirrors wemarketplus-backend/src/billing/billing.constants.ts.
export const SubscriptionStatus = {
  Active: 'active',
  Trialing: 'trialing',
  PastDue: 'past_due',
  Suspended: 'suspended',
  Canceled: 'canceled',
} as const;
export type SubscriptionStatus =
  (typeof SubscriptionStatus)[keyof typeof SubscriptionStatus];
