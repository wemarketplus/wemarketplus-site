import {
  Activity,
  Bell,
  Bot,
  Building2,
  Calendar,
  ClipboardList,
  Contact,
  CreditCard,
  Goal,
  Heart,
  LayoutDashboard,
  LineChart,
  Map,
  MessagesSquare,
  Phone,
  Pin,
  Plug,
  ScrollText,
  ShieldCheck,
  Sparkles,
  Stethoscope,
  Target,
  TrendingUp,
  Trophy,
  Upload,
  UserPlus,
  Users,
  Wrench,
} from 'lucide-react';
import type { ComponentType } from 'react';
import {
  Role,
  STAFF_ROLES,
  ADMIN_ONLY,
  CL_MANAGEMENT_ROLES,
  CL_SALES_ROLES,
  CL_FINANCIAL_ROLES,
  CL_INVENTORY_ROLES,
  CL_MAINTENANCE_ROLES,
  CL_HOUSEKEEPING_ROLES,
  CL_MAKE_READY_ROLES,
} from '@/shared/rbac';
import { Product, Tier, tierIncludes } from '@/shared/types';

export interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string }>;
  // Roles allowed to see the item. Omit to show to every authenticated user.
  allow?: readonly Role[];
  // Product the item belongs to. Omit for items shown across both products.
  product?: Product;
  // Minimum tier needed to see the item (product-aware). Omit for items
  // available to every tier.
  minTier?: Tier;
  // Highest tier at which the item still shows. Used for modules the higher
  // tiers streamline away (e.g. CommunityLink drops GPS/Mileage/Outreach log
  // from the sidebar at Gold/Max). Omit for items with no upper bound.
  maxTier?: Tier;
}

export interface NavSection {
  id: string;
  label: string;
  items: readonly NavItem[];
}

// --- Cross-product MAIN section ----------------------------------------

const MAIN_SECTION: NavSection = {
  id: 'main',
  label: 'Main',
  items: [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/notifications', label: 'Notifications', icon: Bell },
  ],
};

// --- Records (cross-product grant CRM — contacts & employer companies) --

const RECORDS_SECTION: NavSection = {
  id: 'records',
  label: 'Records',
  items: [
    { to: '/contacts', label: 'Contacts', icon: Contact },
    { to: '/companies', label: 'Companies', icon: Building2 },
    { to: '/documents', label: 'Documents', icon: ScrollText },
  ],
};

// --- Financial (cross-product) ----------------------------------------------

// Back-office finance — management/staff only. A field-sales or field-ops
// persona (Marketer, Maintenance, Housekeeping) never sees these.
const FINANCIAL_SECTION: NavSection = {
  id: 'financial',
  label: 'Financial',
  items: [
    { to: '/finance', label: 'Finance overview', icon: CreditCard, allow: STAFF_ROLES },
    { to: '/invoices', label: 'Invoices', icon: ClipboardList, allow: STAFF_ROLES },
    { to: '/contracts', label: 'Contracts', icon: ScrollText, allow: STAFF_ROLES },
  ],
};

// --- Grants domain (cross-product) ------------------------------------------
// Grant-CRM back office — management/staff only.
const GRANTS_SECTION: NavSection = {
  id: 'grants',
  label: 'Grants',
  items: [
    { to: '/funding', label: 'Funding', icon: Target, allow: STAFF_ROLES },
    { to: '/applications', label: 'Applications', icon: ClipboardList, allow: STAFF_ROLES },
    { to: '/agreements', label: 'Agreements', icon: ScrollText, allow: STAFF_ROLES },
    { to: '/wibs', label: 'WIBs', icon: Users, allow: STAFF_ROLES },
  ],
};

// --- Operations records (cross-product) -------------------------------------
// Locations/territories/providers config — management/staff only.
const OPERATIONS_RECORDS_SECTION: NavSection = {
  id: 'ops-records',
  label: 'Operations',
  items: [
    { to: '/locations', label: 'Locations', icon: Pin, allow: STAFF_ROLES },
    { to: '/territories-list', label: 'Territories', icon: Map, allow: STAFF_ROLES },
    { to: '/training-providers', label: 'Training providers', icon: Wrench, allow: STAFF_ROLES },
  ],
};

// --- HospiceLink sections (mirrors wemarketplus-site/crm-pro.html) -----

const HOSPICELINK_MARKETING: NavSection = {
  id: 'hl-marketing',
  label: 'Marketing',
  items: [
    { to: '/prospects', label: 'Prospects', icon: UserPlus, product: Product.HospiceLink },
    { to: '/referrals', label: 'Referral sources', icon: Heart, product: Product.HospiceLink },
    { to: '/pipeline', label: 'Pipeline', icon: LineChart, product: Product.HospiceLink },
    { to: '/territories', label: 'Territories', icon: Map, product: Product.HospiceLink },
    { to: '/scheduling', label: 'Smart scheduling', icon: Calendar, product: Product.HospiceLink, minTier: Tier.Gold },
  ],
};

const HOSPICELINK_ACTIVITY: NavSection = {
  id: 'hl-activity',
  label: 'Activity',
  items: [
    { to: '/activity/calendar', label: 'Follow-up calendar', icon: Calendar, product: Product.HospiceLink },
    { to: '/activity/notes', label: 'Notes', icon: ScrollText, product: Product.HospiceLink },
    { to: '/activity/reminders', label: 'Reminders', icon: Pin, product: Product.HospiceLink },
    { to: '/activity/goals', label: 'Daily goals', icon: Goal, product: Product.HospiceLink },
    { to: '/activity/ai', label: 'AI assistant', icon: Sparkles, product: Product.HospiceLink },
  ],
};

const HOSPICELINK_CLINICAL: NavSection = {
  id: 'hl-clinical',
  label: 'Clinical (Gold)',
  items: [
    { to: '/clinical/family', label: 'Family communication', icon: MessagesSquare, product: Product.HospiceLink, minTier: Tier.Gold },
    { to: '/clinical/messaging', label: 'Secure messaging', icon: MessagesSquare, product: Product.HospiceLink, minTier: Tier.Gold },
    { to: '/clinical/admissions', label: 'Admission workflow', icon: Stethoscope, product: Product.HospiceLink, minTier: Tier.Gold },
  ],
};

const HOSPICELINK_INTELLIGENCE: NavSection = {
  id: 'hl-intelligence',
  label: 'Intelligence (Admin)',
  items: [
    { to: '/intelligence/revenue', label: 'Revenue intelligence', icon: TrendingUp, product: Product.HospiceLink, minTier: Tier.Gold, allow: STAFF_ROLES },
    { to: '/intelligence/marketing-roi', label: 'Marketing ROI', icon: Activity, product: Product.HospiceLink, minTier: Tier.Gold, allow: STAFF_ROLES },
    { to: '/intelligence/leaderboard', label: 'Leaderboard', icon: Trophy, product: Product.HospiceLink, minTier: Tier.Gold, allow: STAFF_ROLES },
  ],
};

const HOSPICELINK_INTEGRATIONS: NavSection = {
  id: 'hl-integrations',
  label: 'Integrations',
  items: [
    { to: '/integrations/import', label: 'Data import', icon: Upload, product: Product.HospiceLink },
    { to: '/integrations/aircall', label: 'Aircall phone', icon: Phone, product: Product.HospiceLink, minTier: Tier.Gold },
    { to: '/integrations/playbooks', label: 'Playbook generator', icon: Bot, product: Product.HospiceLink, minTier: Tier.Max },
  ],
};

const HOSPICELINK_COMPLIANCE: NavSection = {
  id: 'hl-compliance',
  label: 'Compliance (Admin)',
  items: [
    { to: '/compliance', label: 'HIPAA readiness', icon: ShieldCheck, product: Product.HospiceLink, minTier: Tier.Gold, allow: ADMIN_ONLY },
    { to: '/compliance/audit', label: 'Audit log', icon: ScrollText, product: Product.HospiceLink, minTier: Tier.Gold, allow: ADMIN_ONLY },
    { to: '/compliance/threat-monitor', label: 'Threat monitor', icon: ShieldCheck, product: Product.HospiceLink, minTier: Tier.Gold, allow: ADMIN_ONLY },
  ],
};

// --- CommunityLink sections (mirrors communitylink dashboard.html) -----

// Sales & outreach is the CommunityLink baseline (Pro+). Visible to sales and
// management roles; field-only roles (Maintenance/Housekeeping) don't see it.
const COMMUNITYLINK_SALES: NavSection = {
  id: 'cl-sales',
  label: 'Sales & outreach',
  items: [
    { to: '/leads', label: 'Lead pipeline', icon: LineChart, product: Product.CommunityLink, allow: CL_SALES_ROLES },
    { to: '/tasks', label: 'Tasks', icon: ClipboardList, product: Product.CommunityLink, allow: CL_SALES_ROLES },
    { to: '/cl-referrals', label: 'Referral sources', icon: Heart, product: Product.CommunityLink, allow: CL_SALES_ROLES },
    { to: '/paid-referrals', label: 'Paid referral portal', icon: Heart, product: Product.CommunityLink, allow: CL_SALES_ROLES },
    { to: '/tours', label: 'Tour scheduler', icon: Calendar, product: Product.CommunityLink, allow: CL_SALES_ROLES },
    // GPS / Mileage / Outreach log are the Pro-tier field-outreach tools. Gold
    // and Max streamline the sidebar and drop them (maxTier: Pro).
    { to: '/outreach/checkin', label: 'GPS check-in', icon: Target, product: Product.CommunityLink, allow: CL_SALES_ROLES, maxTier: Tier.Pro },
    { to: '/outreach/mileage', label: 'Mileage', icon: Map, product: Product.CommunityLink, allow: CL_SALES_ROLES, maxTier: Tier.Pro },
    { to: '/outreach/log', label: 'Outreach log', icon: ScrollText, product: Product.CommunityLink, allow: CL_SALES_ROLES, maxTier: Tier.Pro },
  ],
};

// Operations is a CommunityLink GOLD-tier bundle (mirrors the pricing page and
// the /demo/communitylink/gold sidebar). Every item requires Gold+.
const COMMUNITYLINK_OPERATIONS: NavSection = {
  id: 'cl-operations',
  label: 'Operations',
  items: [
    // Per-role visibility mirrors the demo: management + Sales/Admissions see
    // all of Operations; each field role sees only its own module plus the
    // shared make-ready board.
    { to: '/operations/communities', label: 'Communities', icon: Building2, product: Product.CommunityLink, minTier: Tier.Gold, allow: CL_INVENTORY_ROLES },
    { to: '/operations/inventory', label: 'Apartment inventory', icon: Building2, product: Product.CommunityLink, minTier: Tier.Gold, allow: CL_INVENTORY_ROLES },
    { to: '/operations/make-ready', label: 'Make-ready board', icon: ClipboardList, product: Product.CommunityLink, minTier: Tier.Gold, allow: CL_MAKE_READY_ROLES },
    { to: '/operations/maintenance', label: 'Maintenance', icon: Wrench, product: Product.CommunityLink, minTier: Tier.Gold, allow: CL_MAINTENANCE_ROLES },
    { to: '/operations/housekeeping', label: 'Housekeeping', icon: Wrench, product: Product.CommunityLink, minTier: Tier.Gold, allow: CL_HOUSEKEEPING_ROLES },
  ],
};

// Financial is a CommunityLink MAX-tier bundle (top tier, $1,999). Staff-only
// AND Max+. Reports stays Gold+ (available once Operations is unlocked).
const COMMUNITYLINK_FINANCIAL: NavSection = {
  id: 'cl-financial',
  label: 'Financial',
  items: [
    // Ledger + leakage are Max-tier financials; Sales/Admissions gets them too
    // (per the Max demo). Reports is available from Pro upward to management.
    { to: '/financial/ledger', label: 'Financial ledger', icon: TrendingUp, product: Product.CommunityLink, allow: CL_FINANCIAL_ROLES, minTier: Tier.Max },
    { to: '/financial/leakage', label: 'Revenue leakage', icon: Activity, product: Product.CommunityLink, allow: CL_FINANCIAL_ROLES, minTier: Tier.Max },
    { to: '/financial/concessions', label: 'Concession approvals', icon: TrendingUp, product: Product.CommunityLink, allow: CL_FINANCIAL_ROLES, minTier: Tier.Max },
    { to: '/financial/competitors', label: 'Competitor intel', icon: Activity, product: Product.CommunityLink, allow: CL_FINANCIAL_ROLES, minTier: Tier.Max },
    { to: '/financial/loc', label: 'LOC calculator', icon: TrendingUp, product: Product.CommunityLink, allow: CL_FINANCIAL_ROLES, minTier: Tier.Max },
    { to: '/reports', label: 'Reports', icon: ScrollText, product: Product.CommunityLink, allow: CL_MANAGEMENT_ROLES },
  ],
};

// --- Admin (always visible to admins, both products) -------------------

const ADMIN_SECTION: NavSection = {
  id: 'admin',
  label: 'Admin',
  items: [
    { to: '/users', label: 'Team', icon: Users, allow: STAFF_ROLES },
    { to: '/permissions', label: 'Roles & permissions', icon: ShieldCheck, allow: ADMIN_ONLY },
    { to: '/billing', label: 'Billing', icon: CreditCard, allow: ADMIN_ONLY },
    // Settings is admin/owner-only. The demo shows it under Administrator and
    // Owner but NOT the Executive Director (who gets Reports but not Settings),
    // so this is ADMIN_ONLY, not the broader management group.
    { to: '/settings', label: 'Settings', icon: Plug, allow: ADMIN_ONLY },
  ],
};

// --- Composed map ------------------------------------------------------

export const SECTIONS_BY_PRODUCT: Record<Product, readonly NavSection[]> = {
  [Product.HospiceLink]: [
    MAIN_SECTION,
    RECORDS_SECTION,
    HOSPICELINK_MARKETING,
    HOSPICELINK_ACTIVITY,
    HOSPICELINK_CLINICAL,
    HOSPICELINK_INTELLIGENCE,
    GRANTS_SECTION,
    FINANCIAL_SECTION,
    OPERATIONS_RECORDS_SECTION,
    HOSPICELINK_INTEGRATIONS,
    HOSPICELINK_COMPLIANCE,
    ADMIN_SECTION,
  ],
  // CommunityLink shows ONLY its own modules — no grant-CRM cross-product
  // sections (Grants, the cross-product Financial, or Operations-records). The
  // sections here mirror the /demo/communitylink/* sidebars, and each collapses
  // by plan tier: Pro sees Sales & outreach; Gold adds Operations + Reports; Max
  // adds Financial ledger/leakage (see minTier on those sections' items).
  [Product.CommunityLink]: [
    MAIN_SECTION,
    RECORDS_SECTION,
    COMMUNITYLINK_SALES,
    COMMUNITYLINK_OPERATIONS,
    COMMUNITYLINK_FINANCIAL,
    ADMIN_SECTION,
  ],
};

// Returns true when the user's current role + tier permit the item. Tier
// comparison is product-aware (CommunityLink orders tiers Pro<Gold<Max, unlike
// HospiceLink's Pro<Max<Gold), so the caller passes the active product.
export function isNavItemVisible(
  item: NavItem,
  product: Product,
  role: Role | null,
  tier: Tier,
): boolean {
  if (item.allow && !(role && item.allow.includes(role))) return false;
  if (item.minTier && !tierIncludes(product, tier, item.minTier)) return false;
  // maxTier is an upper bound: the item shows only up to (and including) that
  // tier. tierIncludes(maxTier, current) is true when current <= maxTier.
  if (item.maxTier && !tierIncludes(product, item.maxTier, tier)) return false;
  return true;
}
