import { Product, type ProductEntitlement } from '@/shared/types';
import type { AuthenticatedUser } from '@/modules/auth/types/authTypes';

// The products a user can actually use. Prefers the `entitlements` array (the
// authoritative multi-product source); falls back to the single legacy
// `product` scalar for older backends that don't yet ship entitlements, and to
// HospiceLink as the ultimate default (matches the rest of the app).
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

// Whether the user is entitled to a given product (the client-side mirror of
// the backend ProductGuard). Nav hiding and route guards both build on this.
export function hasProductAccess(
  user: AuthenticatedUser | null,
  product: Product,
): boolean {
  return entitledProducts(user).includes(product);
}

// Resolves the effective active product: the stored selection when the user is
// still entitled to it, otherwise their primary product. Keeps a stale/persisted
// selection from ever surfacing a dashboard the user can't access.
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
