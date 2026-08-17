import { Role } from '@/shared/rbac';
import { Product } from '@/shared/types';

/**
 * The base role a NEW custom role starts on, per product.
 *
 * The rule is "start from the least permission", so an admin who names a role and
 * saves without touching this picker has created something harmless. That is a
 * per-product answer, because the two products share no field personas: Caregiver
 * is a HospiceLink role and appears in no CommunityLink role group at all.
 *
 * A single shared default of Caregiver is what shipped, and on CommunityLink it
 * opened the form onto an EMPTY tab list — "The selected role has no tabs of its
 * own to choose from" — because no CommunityLink nav item admits Caregiver. The
 * guide's whole custom-role flow ("check the box next to every tab that person
 * should be able to see") had nothing to check.
 *
 * Housekeeping is CommunityLink's narrowest role: its own module, the shared
 * make-ready board, Tasks, and two read-only Max surfaces. Maintenance is within
 * one item of it, so the choice between the two is a tie broken arbitrarily —
 * what matters is that it is a CommunityLink role with a non-empty catalogue.
 */
export const DEFAULT_CUSTOM_ROLE_BASE: Record<Product, Role> = {
  [Product.HospiceLink]: Role.Caregiver,
  [Product.CommunityLink]: Role.Housekeeping,
};
