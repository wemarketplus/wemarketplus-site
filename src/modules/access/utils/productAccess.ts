import { Product, type ProductEntitlement } from '@/shared/types';
import type { AuthenticatedUser } from '@/modules/auth/types/authTypes';

/**
 * DASHBOARD ACCESS vs. BILLING ENTITLEMENT — two different questions.
 *
 * `switchableProducts` / `hasProductAccess` answer "which dashboards may this
 * signed-in user OPEN": both of them, always. One login is one session, and the
 * console can render either dashboard for it.
 *
 * `entitledProducts` / `entitlementForProduct` / `tierForProduct` answer "what
 * has this tenant PAID FOR": unchanged, and still the only input to tier/feature
 * gating (navigationConfig's minTier/maxTier, RequireEntitlement, the backend
 * TierGuard). Nothing here relaxes those.
 *
 * These used to be the same function, which is why a single-product tenant had
 * no switcher and a switch to a non-entitled dashboard was silently dropped.
 */

// Every dashboard the console can render. Order is the order the switcher menu
// lists them in.
export const SWITCHABLE_PRODUCTS: readonly Product[] = [
  Product.HospiceLink,
  Product.CommunityLink,
];

// The dashboards a signed-in user may switch between: BOTH, for every
// authenticated user, whatever their role or the tenant's entitlements. Empty
// when there is no user — no session, no dashboards.
export function switchableProducts(user: AuthenticatedUser | null): Product[] {
  return user ? [...SWITCHABLE_PRODUCTS] : [];
}

// The products the TENANT IS BILLED FOR. Prefers the `entitlements` array (the
// authoritative multi-product source); falls back to the single legacy
// `product` scalar for older backends that don't yet ship entitlements, and to
// HospiceLink as the ultimate default (matches the rest of the app).
//
// NOT dashboard access — use hasProductAccess/switchableProducts for that. This
// is the plan question: which product's tier applies, what billing shows.
export function entitledProducts(user: AuthenticatedUser | null): Product[] {
  if (!user) return [];
  const active = (user.entitlements ?? []).filter((e) => e.isActive);
  if (active.length > 0) {
    // De-dupe while preserving order (primary product tends to come first).
    return [...new Set(active.map((e) => e.product))];
  }
  return [user.product ?? Product.HospiceLink];
}

// The user's default/primary product — the legacy scalar when present, else the
// first entitlement. Used as the initial active dashboard after login.
export function primaryProduct(user: AuthenticatedUser | null): Product {
  if (!user) return Product.HospiceLink;
  if (user.product) return user.product;
  return entitledProducts(user)[0] ?? Product.HospiceLink;
}

/**
 * Whether the user may OPEN a given dashboard — the client-side mirror of the
 * backend ProductGuard, which likewise admits any authenticated tenant user to
 * either product surface (see CROSS_PRODUCT_DASHBOARD_ACCESS there).
 *
 * True for both products for anyone with a session. This is deliberately NOT an
 * entitlement check: it used to be `entitledProducts(user).includes(product)`,
 * which made the switcher a no-op (useActiveProduct drops the dispatch) and made
 * every route of a non-entitled dashboard bounce home (RequireProduct).
 *
 * What still gates, unchanged, once inside a dashboard: role groups
 * (`allow` in navigationConfig, ProtectedRoute/RoleGate, backend @Roles) and
 * plan tier (minTier/maxTier, RequireEntitlement, backend TierGuard). Opening a
 * dashboard is not the same as being allowed into its modules.
 */
export function hasProductAccess(
  user: AuthenticatedUser | null,
  product: Product,
): boolean {
  return switchableProducts(user).includes(product);
}

// Resolves the effective active product: the stored selection when the user may
// open it, otherwise their primary product. A persisted selection now survives
// for both dashboards; it is still discarded when there is no session, so the
// next login starts from its own primary product.
export function resolveActiveProduct(
  user: AuthenticatedUser | null,
  stored: Product | null,
): Product {
  if (stored && hasProductAccess(user, stored)) return stored;
  return primaryProduct(user);
}

// The entitlement record for a specific product — the matching `entitlements`
// row, or a synthesized one from the legacy scalar when it names that product.
// Returns undefined when the user isn't entitled to the product.
export function entitlementForProduct(
  user: AuthenticatedUser | null,
  product: Product,
): ProductEntitlement | undefined {
  const row = (user?.entitlements ?? []).find(
    (e) => e.isActive && e.product === product,
  );
  if (row) return row;
  if (user?.product === product) {
    return {
      product,
      tier: user.tier ?? '',
      subscriptionStatus: user.subscriptionStatus,
      isActive: true,
    };
  }
  return undefined;
}

// The raw backend tier for a specific product (the entitlement's tier, else the
// legacy scalar when it matches that product). Normalize via normalizeTier()
// before comparing against the UI Tier enum.
export function tierForProduct(
  user: AuthenticatedUser | null,
  product: Product,
): string | undefined {
  return entitlementForProduct(user, product)?.tier;
}
