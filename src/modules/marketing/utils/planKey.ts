import { Product, Tier } from '@/shared/types';

// Maps a marketing (product, tier) pair to the backend billing catalog key
// consumed by POST /billing/checkout { planKey }. Keys are verified against
// wemarketplus-backend/src/billing/plan-catalog.ts (PLAN_CATALOG):
//   HospiceLink  -> hl_pro / hl_max / hl_gold
//   CommunityLink -> cl_pro / cl_gold / cl_max
const PLAN_KEY_BY_PRODUCT_TIER: Record<Product, Record<Tier, string>> = {
  [Product.HospiceLink]: {
    [Tier.Pro]: 'hl_pro',
    [Tier.Max]: 'hl_max',
    [Tier.Gold]: 'hl_gold',
  },
  [Product.CommunityLink]: {
    [Tier.Pro]: 'cl_pro',
    [Tier.Gold]: 'cl_gold',
    [Tier.Max]: 'cl_max',
  },
};

// Resolves the backend catalog planKey for a marketing (product, tier) pair.
export function planKeyFor(product: Product, tier: Tier): string {
  return PLAN_KEY_BY_PRODUCT_TIER[product][tier];
}

// Builds the onboarding entry href that carries the chosen plan through the
// signup funnel, e.g. /onboarding?plan=hl_max.
export function onboardingHrefForPlan(product: Product, tier: Tier): string {
  return `/onboarding?plan=${planKeyFor(product, tier)}`;
}
