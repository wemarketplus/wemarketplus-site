import {
  SECTIONS_BY_PRODUCT,
  navItemKey,
  type NavItem,
} from '@/shared/config/navigationConfig';
import { PRODUCT_LABELS, Product } from '@/shared/types';
import type { Role } from '@/shared/rbac';

export interface NavCatalogEntry {
  key: string;
  label: string;
}

export interface NavCatalogGroup {
  /** `<product> · <section>`, e.g. "HospiceLink · Activity". */
  title: string;
  entries: NavCatalogEntry[];
}

/**
 * The tab list an admin picks from when building a custom role, grouped exactly as
 * the sidebar groups it.
 *
 * Derived from SECTIONS_BY_PRODUCT rather than hand-maintained: the checkbox list and
 * the real sidebar must be the same set, or an admin ticks tabs that do not exist and
 * cannot tick ones that do. Adding a module to the nav therefore adds it here for free.
 *
 * FILTERED BY THE CHOSEN BASE ROLE. A custom role can only ever narrow what its base
 * role already sees (see isNavItemVisible), so offering the rest would be offering
 * checkboxes that do nothing — the most confusing possible control. Change the base
 * role in the form and the catalogue changes with it.
 *
 * Tier is deliberately NOT applied. The tenant's tier can change (and differs per
 * product for dual-product tenants), so a Gold-only tab is worth keeping checked
 * through a downgrade rather than silently dropping from the role's definition. Tier
 * gating still applies at render time; it is simply not part of this list.
 *
 * `comingSoon` rows are excluded: they are announcements, not destinations, and there
 * is nothing to grant or withhold.
 *
 * Both products are listed. A dual-product tenant's custom role legitimately spans
 * both dashboards, and for a single-product tenant the other product's groups are
 * simply never rendered by the sidebar.
 */
export function buildNavCatalog(baseRole: Role): NavCatalogGroup[] {
  const groups: NavCatalogGroup[] = [];
  for (const product of [Product.HospiceLink, Product.CommunityLink]) {
    for (const section of SECTIONS_BY_PRODUCT[product]) {
      const entries = section.items
        .filter((item: NavItem) => !item.comingSoon)
        // The item's own product tag wins over the group it is composed into —
        // ADMIN_SECTION holds one row per product for the same path.
        .filter((item) => !item.product || item.product === product)
        .filter((item) => !item.allow || item.allow.includes(baseRole))
        .map((item) => ({
          key: navItemKey(section.id, item),
          label: item.label,
        }));
      // De-dupe by key: two tier windows of one item (Occupancy overview) are one
      // checkbox, since they share a section and a path.
      const unique = [
        ...new Map(entries.map((entry) => [entry.key, entry])).values(),
      ];
      if (unique.length > 0) {
        groups.push({
          title: `${PRODUCT_LABELS[product]} · ${section.label}`,
          entries: unique,
        });
      }
    }
  }
  return groups;
}

/** Every key in the catalogue — backs the "select all" affordance. */
export const allCatalogKeys = (groups: NavCatalogGroup[]): string[] =>
  groups.flatMap((group) => group.entries.map((entry) => entry.key));
