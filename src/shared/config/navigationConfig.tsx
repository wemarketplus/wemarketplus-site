import {
  Activity,
  Bell,
  Bot,
  Building2,
  Calendar,
  ClipboardList,
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
import { Role, STAFF_ROLES, ADMIN_ONLY } from '@/shared/rbac';
import { Product, Tier, tierIncludes } from '@/shared/types';

export interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<{ className?: string }>;
  // Roles allowed to see the item. Omit to show to every authenticated user.
  allow?: readonly Role[];
  // Product the item belongs to. Omit for items shown across both products.
  product?: Product;
  // Minimum tier needed to see the item (gold > max > pro). Omit for items
  // available to every tier.
  minTier?: Tier;
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

const COMMUNITYLINK_SALES: NavSection = {
  id: 'cl-sales',
  label: 'Sales & outreach',
  items: [
    { to: '/leads', label: 'Lead pipeline', icon: LineChart, product: Product.CommunityLink },
    { to: '/cl-referrals', label: 'Referral sources', icon: Heart, product: Product.CommunityLink },
    { to: '/tours', label: 'Tour scheduler', icon: Calendar, product: Product.CommunityLink },
    { to: '/outreach/checkin', label: 'GPS check-in', icon: Target, product: Product.CommunityLink },
    { to: '/outreach/mileage', label: 'Mileage', icon: Map, product: Product.CommunityLink },
    { to: '/outreach/log', label: 'Outreach log', icon: ScrollText, product: Product.CommunityLink },
  ],
};

const COMMUNITYLINK_OPERATIONS: NavSection = {
  id: 'cl-operations',
  label: 'Operations',
  items: [
    { to: '/operations/inventory', label: 'Apartment inventory', icon: Building2, product: Product.CommunityLink },
    { to: '/operations/make-ready', label: 'Make-ready board', icon: ClipboardList, product: Product.CommunityLink },
    { to: '/operations/maintenance', label: 'Maintenance', icon: Wrench, product: Product.CommunityLink },
    { to: '/operations/housekeeping', label: 'Housekeeping', icon: Wrench, product: Product.CommunityLink },
  ],
};

const COMMUNITYLINK_FINANCIAL: NavSection = {
  id: 'cl-financial',
  label: 'Financial',
  items: [
    { to: '/financial/ledger', label: 'Financial ledger', icon: TrendingUp, product: Product.CommunityLink, allow: STAFF_ROLES },
    { to: '/financial/leakage', label: 'Revenue leakage', icon: Activity, product: Product.CommunityLink, allow: STAFF_ROLES },
    { to: '/reports', label: 'Reports', icon: ScrollText, product: Product.CommunityLink, allow: STAFF_ROLES },
  ],
};

// --- Admin (always visible to admins, both products) -------------------

const ADMIN_SECTION: NavSection = {
  id: 'admin',
  label: 'Admin',
  items: [
    { to: '/users', label: 'Team', icon: Users, allow: STAFF_ROLES },
    { to: '/permissions', label: 'Roles & permissions', icon: ShieldCheck, allow: ADMIN_ONLY },
    { to: '/billing', label: 'Billing', icon: CreditCard },
    { to: '/settings', label: 'Settings', icon: Plug },
  ],
};

// --- Composed map ------------------------------------------------------

export const SECTIONS_BY_PRODUCT: Record<Product, readonly NavSection[]> = {
  [Product.HospiceLink]: [
    MAIN_SECTION,
    HOSPICELINK_MARKETING,
    HOSPICELINK_ACTIVITY,
    HOSPICELINK_CLINICAL,
    HOSPICELINK_INTELLIGENCE,
    HOSPICELINK_INTEGRATIONS,
    HOSPICELINK_COMPLIANCE,
    ADMIN_SECTION,
  ],
  [Product.CommunityLink]: [
    MAIN_SECTION,
    COMMUNITYLINK_SALES,
    COMMUNITYLINK_OPERATIONS,
    COMMUNITYLINK_FINANCIAL,
    ADMIN_SECTION,
  ],
};

// Returns true when the user's current role + tier permit the item.
export function isNavItemVisible(
  item: NavItem,
  role: Role | null,
  tier: Tier,
): boolean {
  if (item.allow && !(role && item.allow.includes(role))) return false;
  if (item.minTier && !tierIncludes(tier, item.minTier)) return false;
  return true;
}
