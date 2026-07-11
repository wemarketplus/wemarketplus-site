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

// Tier rank — higher numbers unlock more features. The two products order
// their tiers DIFFERENTLY (mirror wemarketplus-backend/src/billing/plan-catalog
// TIER_RANK): HospiceLink is Pro < Max < Gold (Gold top, $749), CommunityLink
// is Pro < Gold < Max (Max top, $1,999). Ranking must therefore be product-aware
// — a single shared order would invert one product's tiers.
const TIER_RANK_BY_PRODUCT: Record<Product, Record<Tier, number>> = {
  [Product.HospiceLink]: {
    [Tier.Pro]: 1,
    [Tier.Max]: 2,
    [Tier.Gold]: 3,
  },
  [Product.CommunityLink]: {
    [Tier.Pro]: 1,
    [Tier.Gold]: 2,
    [Tier.Max]: 3,
  },
};

// Whether a tenant on `current` tier (of `product`) has access to a feature
// that requires `required` tier. Product-aware so CommunityLink Gold/Max are
// ranked correctly.
export const tierIncludes = (
  product: Product,
  current: Tier,
  required: Tier,
): boolean =>
  TIER_RANK_BY_PRODUCT[product][current] >=
  TIER_RANK_BY_PRODUCT[product][required];

// The backend CrmTier enum prefixes CommunityLink tiers ('cl_gold'); the UI
// tracks the product separately, so strip the prefix and validate. Returns
// undefined for unknown/absent values so callers can apply their own default.
export const normalizeTier = (raw?: string): Tier | undefined => {
  if (!raw) return undefined;
  const t = raw.startsWith('cl_') ? raw.slice(3) : raw;
  return t === Tier.Pro || t === Tier.Gold || t === Tier.Max
    ? (t as Tier)
    : undefined;
};

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
