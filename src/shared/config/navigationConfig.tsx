import {
  Activity,
  Bell,
  BellRing,
  Video,
  Gauge,
  Bot,
  Building2,
  Calendar,
  CalendarClock,
  Car,
  CalendarCheck,
  ClipboardList,
  Contact,
  CreditCard,
  Gift,
  GitBranch,
  Inbox,
  Goal,
  Heart,
  LayoutDashboard,
  LineChart,
  Map,
  MapPin,
  MessagesSquare,
  NotebookPen,
  Phone,
  PieChart,
  Pin,
  Plug,
  Receipt,
  ScrollText,
  Settings2,
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
  ListChecks,
  QrCode,
  MapPinned,
  UserCog,
  RotateCcw,
} from 'lucide-react';
import type { ComponentType } from 'react';
import {
  Role,
  STAFF_ROLES,
  ADMIN_ONLY,
  HL_MANAGEMENT_ROLES,
  HL_MARKETING_ROLES,
  HL_CLINICAL_ROLES,
  HL_FIELD_ROLES,
  CL_MANAGEMENT_ROLES,
  CL_SALES_ROLES,
  CL_FINANCIAL_ROLES,
  CL_INVENTORY_ROLES,
  CL_MAINTENANCE_ROLES,
  CL_HOUSEKEEPING_ROLES,
  CL_MAKE_READY_ROLES,
  CL_ALL_ROLES,
  CL_UNIT_STATUS_ROLES,
  CL_MAINTENANCE_VIEW_ROLES,
  CL_COMPETITOR_INTEL_ROLES,
  CL_FIELD_ACTIVITY_ROLES,
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
  /**
   * Announced but not yet built. The Sidebar renders these as an inert row with a
   * "Soon" badge — NOT a link, because there is nothing to route to.
   *
   * Exists because the nurse product guide ends with "Coming soon to your view",
   * and a guide that names a screen the sidebar never mentions reads as a broken
   * product rather than a roadmap. `to` is still required and still holds the path
   * the item WILL use: it keys the row, and turning the row into a real link later
   * is then a one-line deletion of this flag.
   */
  comingSoon?: boolean;
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
    { to: '/my-profile', label: 'My profile', icon: UserCog },
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

// --- Grants domain (cross-product) — REMOVED FROM THE SIDEBAR ---------------
//
// DEPRECATED / NOT NEEDED. The Grants section and its three modules (Funding,
// Applications, Agreements) are not part of the product and are slated to be
// removed/purged outright. Per product owner (2026-08-06) they are taken out of
// the sidebar now; the module code, routes and store wiring are left in place
// only so the section can be restored quickly if it turns out to be needed.
// Do NOT build on these modules, and do NOT re-add this section to
// SECTIONS_BY_PRODUCT without product-owner sign-off.
//
// const GRANTS_SECTION: NavSection = {
//   id: 'grants',
//   label: 'Grants',
//   items: [
//     { to: '/funding', label: 'Funding', icon: Target, allow: STAFF_ROLES },
//     { to: '/applications', label: 'Applications', icon: ClipboardList, allow: STAFF_ROLES },
//     { to: '/agreements', label: 'Agreements', icon: ScrollText, allow: STAFF_ROLES },
//     // WIBs (Workforce Investment Boards) used to sit here, hidden. The module,
//     // its route and its store wiring have now been removed outright — a
//     // Grants-domain concept has no meaning in this CRM. The backend endpoints
//     // still exist for the Grants product; nothing in this app calls them.
//   ],
// };

// --- Operations records (cross-product) -------------------------------------
// Locations/territories/providers config — management/staff only.
const OPERATIONS_RECORDS_SECTION: NavSection = {
  id: 'ops-records',
  label: 'Operations',
  items: [
    { to: '/locations', label: 'Locations', icon: Pin, allow: STAFF_ROLES },
    { to: '/territories-list', label: 'Territories', icon: Map, allow: STAFF_ROLES },
    // HIDDEN (intentionally): Training providers module hidden from the frontend
    // by request. Do NOT re-enable without confirming with the product owner.
    // The module code, route, and store wiring still exist; only the nav entry
    // is removed.
    // { to: '/training-providers', label: 'Training providers', icon: Wrench, allow: STAFF_ROLES },
   /* { to: '/training-providers', label: 'Training providers', icon: Wrench, allow: STAFF_ROLES },*/
  ],
};

// --- HospiceLink sections (mirrors wemarketplus-site/crm-pro.html) -----

// Gated to HL_MARKETING_ROLES by default: this section is where account strategy
// and referral-source value live, so Nurse and Caregiver do not see it. Before
// these `allow` lists existed every HospiceLink role saw every item here.
//
// Two rows deliberately depart from the section default, each for a reason spelled
// out at the row: Daily tasks widens to HL_FIELD_ROLES (both clinical guides open
// the day on it, and the queue is self-scoped server-side), and Nurse scheduling
// NARROWS to HL_MANAGEMENT_ROLES (it is the roster, and only management can write
// to it). Per-row `allow` always wins over this paragraph — read the row.
const HOSPICELINK_MARKETING: NavSection = {
  id: 'hl-marketing',
  label: 'Marketing',
  items: [
    // Everything due today, assembled from five modules. First in the section
    // because it is where the day starts.
    //
    // HL_FIELD_ROLES, not HL_MARKETING_ROLES: the nurse guide says "Check Daily
    // Task each morning for anything the system has flagged for you" and the
    // caregiver guide opens with "Check Daily Task first thing", so both clinical
    // personas need it. The queue is self-scoped server-side (DailyQueueService
    // filters every section to the acting user), so a caregiver sees their own
    // tasks and visits — not a marketer's accounts. Backend @Roles widened to
    // match, or the guide's first instruction would 403.
    { to: '/daily-tasks', label: 'Daily tasks', icon: ListChecks, product: Product.HospiceLink, allow: HL_FIELD_ROLES },
    // Standing follow-ups on a prospect; each lands in Daily tasks on its due
    // date. Next to Daily tasks because it is the input to it.
    { to: '/automation', label: 'Automation', icon: BellRing, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    { to: '/re-engagement', label: 'Re-engagement', icon: RotateCcw, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    // Named for the guide's "Click Marketer Leaderboard to see how your whole
    // team is performing side by side". Two items were previously both called
    // "Leaderboard" — this is the base-tier, team-standings one; the Intelligence
    // group's is the Gold admin report that additionally carries revenue.
    { to: '/leaderboard', label: 'Marketer leaderboard', icon: Trophy, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    { to: '/hl-leads', label: 'Inbound leads', icon: Inbox, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    { to: '/prospects', label: 'Prospects', icon: UserPlus, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    { to: '/referrals', label: 'Referral sources', icon: Heart, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    // The contact record every conversion creates. Had no nav entry and no route
    // at all despite being what Prospects and Jobs point at (decision item 1).
    { to: '/hl-contacts', label: 'Hospice contacts', icon: Contact, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    // Issue/revoke the QR links facilities use to submit referrals with no login.
    { to: '/referral-portal', label: 'Referral portal', icon: QrCode, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    { to: '/pipeline', label: 'Pipeline', icon: LineChart, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    { to: '/jobs', label: 'Jobs', icon: ClipboardList, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    { to: '/territories', label: 'Territories', icon: Map, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    // The planning view over the same data: accounts per patch, cold first.
    { to: '/territory-planner', label: 'Territory planner', icon: MapPinned, product: Product.HospiceLink, allow: HL_MARKETING_ROLES },
    // Renamed from "Smart scheduling": the module is nurse rostering now, and a label
    // that does not say what the screen does is how the demo/build gap started.
    //
    // HL_MANAGEMENT_ROLES, not HL_FIELD_ROLES: this is the rostering tool — who is
    // on shift across the team — and nurse-scheduling.controller.ts gates every
    // write (@Post/@Patch/@Delete) to Admin/Owner/Manager. The `allow` mirrors that
    // @Roles list, so the people who can see the screen are the people who can act
    // on it. On HL_FIELD_ROLES a nurse got a live row here, in a Marketing group her
    // guide tells her to ignore, opening a read-only roster of everyone else — while
    // the SAME sidebar offered her a "Soon"-badged "My visit schedule" in Clinical.
    // Two scheduling rows, one live and one promised, is precisely the guide/product
    // mismatch `comingSoon` exists to prevent. The nurse's own-schedule view IS that
    // /clinical/my-schedule row; widen this one back and the pair reappears.
    { to: '/scheduling', label: 'Nurse scheduling', icon: CalendarClock, product: Product.HospiceLink, minTier: Tier.Gold, allow: HL_MANAGEMENT_ROLES },
  ],
};

// HL_FIELD_ROLES: the surfaces every HospiceLink persona works in, including the
// two clinical roles. EVV and mileage are gated at Max because that is the tier
// the pricing page sells "EVV/GPS mileage & compliance log" at.
const HOSPICELINK_ACTIVITY: NavSection = {
  id: 'hl-activity',
  label: 'Activity',
  items: [
    /**
     * THE CALENDAR THE PRODUCT GUIDE MEANS. Every role's guide says "Click Calendar
     * … use the dropdown at the top to switch between My Calendar and All Users",
     * and this is the only screen that has any of that: the month grid, the
     * scope toggle, and the per-user colours. It was labelled "Appointments" while
     * the row below — a flat list of upcoming follow-ups with none of those things —
     * held the name "Calendar", so anyone following the guide clicked the wrong row
     * and concluded the feature was missing.
     *
     * Renamed rather than merged: both screens are real and both are wanted. Only
     * the labels were lying. Routes are untouched, so existing links still resolve.
     */
    { to: '/appointments', label: 'Calendar', icon: CalendarCheck, product: Product.HospiceLink, allow: HL_FIELD_ROLES },
    // Named for what it actually is. Its own page header already said "Upcoming
    // follow-ups"; only the sidebar called it a calendar.
    { to: '/activity/calendar', label: 'Follow-ups', icon: Calendar, product: Product.HospiceLink, allow: HL_FIELD_ROLES },
    // Labelled for both jobs it now does. "Team notes" used to exist only as a tab
    // inside the marketer-only prospect drawer, so clinical staff had no route to a
    // surface their guide tells them to use; the Notes screen now serves as that
    // surface for Nurse and Caregiver, and the label says so rather than leaving
    // them hunting for a "Team notes" row that does not exist. `allow` is unchanged:
    // HL_FIELD_ROLES already covered exactly the personas that needed it.
    { to: '/activity/notes', label: 'Notes & team notes', icon: ScrollText, product: Product.HospiceLink, allow: HL_FIELD_ROLES },
    { to: '/activity/reminders', label: 'Reminders', icon: Pin, product: Product.HospiceLink, allow: HL_FIELD_ROLES },
    { to: '/activity/goals', label: 'Daily goals', icon: Goal, product: Product.HospiceLink, allow: HL_FIELD_ROLES },
    { to: '/activity/ai', label: 'AI assistant', icon: Sparkles, product: Product.HospiceLink, allow: HL_FIELD_ROLES },
    // Previously unreachable: the tables, endpoints and RTK hooks all existed with
    // no nav entry and no route, so EVV was "API only" despite being sold at Max.
    { to: '/field/evv', label: 'Visit verification', icon: MapPin, product: Product.HospiceLink, minTier: Tier.Max, allow: HL_FIELD_ROLES },
    { to: '/field/mileage', label: 'Mileage & expenses', icon: Car, product: Product.HospiceLink, minTier: Tier.Max, allow: HL_FIELD_ROLES },
  ],
};

const HOSPICELINK_CLINICAL: NavSection = {
  id: 'hl-clinical',
  label: 'Clinical (Gold)',
  items: [
    { to: '/clinical/family', label: 'Family communication', icon: MessagesSquare, product: Product.HospiceLink, minTier: Tier.Gold, allow: HL_CLINICAL_ROLES },
    /**
     * Labelled for the screen it actually opens. This route mounts the care-team
     * TELEHEALTH SESSION list (see ClinicalPage's pathname switch), and calling it
     * "Secure messaging" promised a chat product that is not what loads — the one
     * mislabel in the sidebar where the name and the page disagreed outright.
     *
     * There IS a complete messaging backend (src/chat: channels, direct messages,
     * unread counts, presence) with no screen in front of it. Building that screen
     * is a feature, not a rename, so it stays a separate piece of work — but until
     * it exists, no row should claim it. Distinct from "Telehealth & patient portal"
     * below, which is the PATIENT-facing video product and still coming soon.
     */
    { to: '/clinical/messaging', label: 'Care-team telehealth', icon: Video, product: Product.HospiceLink, minTier: Tier.Gold, allow: HL_CLINICAL_ROLES },
    { to: '/clinical/admissions', label: 'Admission workflow', icon: Stethoscope, product: Product.HospiceLink, minTier: Tier.Gold, allow: HL_CLINICAL_ROLES },
    /**
     * The nurse guide's "Coming soon to your view" — announced to the nurse, and
     * to the nurse only (the caregiver guide promises nothing, and management has
     * the roster tool already).
     *
     * "My visit schedule" is deliberately NOT called "Nurse scheduling": that name
     * is taken by the Gold rostering screen in the Marketing group, which is the
     * ADMIN view of who is on shift. What the guide promises a nurse is the
     * opposite — "a dedicated view of your own visit schedule" — and shipping two
     * sidebar rows with near-identical names is how a guide stops matching the
     * product.
     */
    { to: '/clinical/telehealth', label: 'Telehealth & patient portal', icon: Video, product: Product.HospiceLink, minTier: Tier.Gold, allow: [Role.Nurse], comingSoon: true },
    { to: '/clinical/my-schedule', label: 'My visit schedule', icon: CalendarClock, product: Product.HospiceLink, minTier: Tier.Gold, allow: [Role.Nurse], comingSoon: true },
  ],
};

const HOSPICELINK_INTELLIGENCE: NavSection = {
  id: 'hl-intelligence',
  label: 'Intelligence (Admin)',
  items: [
    /**
     * ONE row, not three. IntelligencePage deliberately renders attribution,
     * marketing ROI and the team leaderboard on a single screen over a single
     * window, and it does not switch on the pathname — so the former "Marketing
     * ROI" and "Team performance" rows were three doors into one identical view,
     * which reads as a broken tab. The reports are all still here, as sections of
     * this page. `/intelligence/{marketing-roi,leaderboard}` stay routed (see
     * router.tsx) so old bookmarks keep working; they just have no nav entry.
     */
    { to: '/intelligence/revenue', label: 'Revenue intelligence', icon: TrendingUp, product: Product.HospiceLink, minTier: Tier.Gold, allow: STAFF_ROLES },
    // Automatic 1-10 grade per referring facility. Its own backend feature key
    // (intelligence_referral_scorecard), same Gold rank as the rest of the group.
    { to: '/intelligence/referral-scorecard', label: 'Referral source scorecard', icon: Gauge, product: Product.HospiceLink, minTier: Tier.Gold, allow: STAFF_ROLES },
    // The Executive Director touchpoint that was absent from the 42-module inventory.
    { to: '/intelligence/weekly', label: 'Weekly report', icon: ScrollText, product: Product.HospiceLink, minTier: Tier.Gold, allow: STAFF_ROLES },
  ],
};

const HOSPICELINK_INTEGRATIONS: NavSection = {
  id: 'hl-integrations',
  label: 'Integrations',
  items: [
    // STAFF_ROLES mirrors the backend: data-transfer.controller.ts is
    // @RequirePermission("import_export") and the default permission matrix denies
    // that permission to Caregiver outright, so with no `allow` here a caregiver saw
    // a tab that could only ever 403. The end-user guide files Import Data as an
    // Admin/Office-Manager task, and STAFF_ROLES is the same group that already
    // gates the Admin/Team page in ADMIN_SECTION.
    //
    // This row is also the ONLY entry point to the data EXPORT screen —
    // DataImportExportPage serves both halves. That is deliberate and STAFF_ROLES is
    // right for both: bulk-exporting the tenant's referral book is at least as
    // sensitive as importing into it. Do not widen this on the grounds that "export
    // is read-only".
    { to: '/integrations/import', label: 'Import data', icon: Upload, product: Product.HospiceLink, allow: STAFF_ROLES },
    // HL_MARKETING_ROLES: the Aircall console dials referral accounts and shows the
    // call/text history against them, which is the marketing group's relationship
    // data — a clinical persona has no account to dial from here. Previously the row
    // (and its route) carried the Gold tier gate only, so every role on a Gold tenant
    // saw a phone console. Mirrors the route's `allow`; change one side, change both.
    { to: '/integrations/aircall', label: 'Aircall phone', icon: Phone, product: Product.HospiceLink, minTier: Tier.Gold, allow: HL_MARKETING_ROLES },
    // HL_MARKETING_ROLES mirrors the backend exactly: POST /ai/playbooks already
    // carries `@Roles(...HL_MARKETING_ROLES)`, so with no `allow` here a Nurse and a
    // Caregiver saw a tab that could only ever 403 — the same defect the two rows
    // above were fixed for, left behind because this one had no `allow` line to
    // correct. The end-user guide also files it under the Marketer's tools.
    { to: '/integrations/playbooks', label: 'Playbook generator', icon: Bot, product: Product.HospiceLink, minTier: Tier.Max, allow: HL_MARKETING_ROLES },
  ],
};

const HOSPICELINK_COMPLIANCE: NavSection = {
  id: 'hl-compliance',
  label: 'Compliance (Admin)',
  items: [
    /**
     * `/compliance/readiness`, NOT `/compliance` — the latter is taken by the
     * PUBLIC marketing "Compliance posture" page, declared earlier in the same
     * <Routes>. Two routes with the identical path resolve to whichever is
     * declared first, so an admin clicking this row was thrown out of the app
     * shell onto the marketing site (it reads as "went back to the homepage").
     * The authenticated readiness screen already answered on both paths; this is
     * the one nothing else claims.
     */
    { to: '/compliance/readiness', label: 'HIPAA readiness', icon: ShieldCheck, product: Product.HospiceLink, minTier: Tier.Gold, allow: ADMIN_ONLY },
    { to: '/compliance/audit', label: 'HIPAA audit log', icon: ScrollText, product: Product.HospiceLink, minTier: Tier.Gold, allow: ADMIN_ONLY },
    { to: '/compliance/threat-monitor', label: 'Threat monitor', icon: ShieldCheck, product: Product.HospiceLink, minTier: Tier.Gold, allow: ADMIN_ONLY },
    // NOTE: HospiceLink has no "Alert settings" entry on purpose. Its product
    // guide routes an Office Manager to Notifications > Team alerts for the same
    // controls, and two entry points to one screen is how a guide stops matching
    // the product. CommunityLink keeps its own page (COMMUNITYLINK_ADMIN_SETTINGS).
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
    // Referral Pipeline is a Max-tier addition alongside Lead Pipeline — a
    // stage-grouped view over the same paid-referral data as Paid Referral
    // Portal below (cl/paid-referrals already carries a `stage` field).
    { to: '/referral-pipeline', label: 'Referral pipeline', icon: GitBranch, product: Product.CommunityLink, allow: CL_SALES_ROLES, minTier: Tier.Max },
    // Tasks is visible to every CommunityLink role, including the field roles
    // (Maintenance/Housekeeping) — every role's sidebar in the demo has it.
    { to: '/tasks', label: 'Tasks', icon: ClipboardList, product: Product.CommunityLink, allow: CL_ALL_ROLES },
    { to: '/cl-referrals', label: 'Referral sources', icon: Heart, product: Product.CommunityLink, allow: CL_SALES_ROLES },
    { to: '/paid-referrals', label: 'Paid referral portal', icon: Heart, product: Product.CommunityLink, allow: CL_SALES_ROLES },
    { to: '/tours', label: 'Tour scheduler', icon: Calendar, product: Product.CommunityLink, allow: CL_SALES_ROLES },
    // AI Sales Assistant is CommunityLink-baseline (Pro+, no tier cap) — the
    // Pro demo shows it and Gold/Max's mockups simply don't re-show it
    // (those demos focus on that tier's new capabilities), not a deliberate
    // removal on upgrade. Reuses the same generic, product-agnostic AI
    // assistant page/route already used by HospiceLink.
    { to: '/ai-assistant', label: 'AI sales assistant', icon: Sparkles, product: Product.CommunityLink, allow: CL_SALES_ROLES },
    // GPS check-in / Outreach log are the Pro-tier field-outreach tools. Gold
    // and Max streamline the sidebar and drop them (maxTier: Pro).
    { to: '/outreach/checkin', label: 'GPS check-in', icon: Target, product: Product.CommunityLink, allow: CL_SALES_ROLES, maxTier: Tier.Pro },
    { to: '/outreach/mileage', label: 'Mileage', icon: Map, product: Product.CommunityLink, allow: CL_SALES_ROLES, maxTier: Tier.Pro },
    { to: '/outreach/log', label: 'Outreach log', icon: ScrollText, product: Product.CommunityLink, allow: CL_SALES_ROLES, maxTier: Tier.Pro },
  ],
};

// Occupancy Overview's visible-role-set changes by tier band, which a single
// NavItem's `allow` can't express — so it's two windowed entries, exactly
// like the Mileage / Mileage & Expenses split below. At Gold it's
// Director-only (the Gold demo's Administrator does NOT have it); at Max it
// broadens to the full management + Sales/Admissions group.
const COMMUNITYLINK_MAIN_EXTRA: NavSection = {
  id: 'cl-main-extra',
  label: 'Main',
  items: [
    { to: '/occupancy-overview', label: 'Occupancy overview', icon: PieChart, product: Product.CommunityLink, allow: [Role.SuperAdmin, Role.Director], minTier: Tier.Gold, maxTier: Tier.Gold },
    { to: '/occupancy-overview', label: 'Occupancy overview', icon: PieChart, product: Product.CommunityLink, allow: CL_FINANCIAL_ROLES, minTier: Tier.Max },
  ],
};

// Activity is a CommunityLink MAX-tier bundle: cross-lead activity notes, a
// combined mileage/expense view, gift & gratuity compliance logging, and the
// Aircall phone integration. Owner/Investor gets only Notes/Tasks/Aircall
// (not Mileage & Expenses or Gift & Gratuity) — see CL_FIELD_ACTIVITY_ROLES.
const COMMUNITYLINK_ACTIVITY: NavSection = {
  id: 'cl-activity',
  label: 'Activity',
  items: [
    { to: '/activity-notes', label: 'Activity notes', icon: NotebookPen, product: Product.CommunityLink, allow: CL_SALES_ROLES, minTier: Tier.Max },
    { to: '/outreach/mileage', label: 'Mileage & expenses', icon: Receipt, product: Product.CommunityLink, allow: CL_FIELD_ACTIVITY_ROLES, minTier: Tier.Max },
    { to: '/gift-gratuity', label: 'Gift & gratuity', icon: Gift, product: Product.CommunityLink, allow: CL_FIELD_ACTIVITY_ROLES, minTier: Tier.Max },
    { to: '/aircall', label: 'Aircall — call · text · email', icon: Phone, product: Product.CommunityLink, allow: CL_SALES_ROLES, minTier: Tier.Max },
  ],
};

// Admin-only settings, Max tier (mirrors the Max Administrator "ADMIN" group).
const COMMUNITYLINK_ADMIN_SETTINGS: NavSection = {
  id: 'cl-admin-settings',
  label: 'Admin',
  items: [
    { to: '/alert-settings', label: 'Alert settings', icon: BellRing, product: Product.CommunityLink, allow: ADMIN_ONLY, minTier: Tier.Max },
    { to: '/financial-settings', label: 'Financial settings', icon: Settings2, product: Product.CommunityLink, allow: ADMIN_ONLY, minTier: Tier.Max },
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
    // Max-tier-only read-only surfaces for the field roles (per the Max demo):
    // Unit Status gives Maintenance/Housekeeping apartment-status visibility
    // without inventory write access; Maintenance View gives Housekeeping
    // read-only visibility into maintenance tickets.
    { to: '/operations/unit-status', label: 'Unit Status', icon: Building2, product: Product.CommunityLink, minTier: Tier.Max, allow: CL_UNIT_STATUS_ROLES },
    { to: '/operations/maintenance-view', label: 'Maintenance View', icon: Wrench, product: Product.CommunityLink, minTier: Tier.Max, allow: CL_MAINTENANCE_VIEW_ROLES },
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
    { to: '/financial/competitors', label: 'Competitor intel', icon: Activity, product: Product.CommunityLink, allow: CL_COMPETITOR_INTEL_ROLES, minTier: Tier.Max },
    { to: '/financial/loc', label: 'LOC calculator', icon: TrendingUp, product: Product.CommunityLink, allow: CL_FINANCIAL_ROLES, minTier: Tier.Max },
    { to: '/reports', label: 'Reports', icon: ScrollText, product: Product.CommunityLink, allow: CL_MANAGEMENT_ROLES },
  ],
};

// --- Admin (always visible to admins, both products) -------------------

const ADMIN_SECTION: NavSection = {
  id: 'admin',
  label: 'Admin',
  items: [
    // The HospiceLink product guide instructs an Office Manager to "Click Admin
    // in the left menu" and expects seat counts, team-wide mileage and the
    // invite action there — which is exactly this page. Split per product so the
    // rename does not touch CommunityLink, whose own guide says "Team".
    { to: '/users', label: 'Admin', icon: Users, product: Product.HospiceLink, allow: STAFF_ROLES },
    { to: '/users', label: 'Team', icon: Users, product: Product.CommunityLink, allow: STAFF_ROLES },
    { to: '/permissions', label: 'Roles & permissions', icon: ShieldCheck, allow: ADMIN_ONLY },
    // HospiceLink's entry to the same cross-product screen CommunityLink lists
    // under its own Admin section. Holds `marketing_spend_monthly`, the only cost
    // input behind Revenue Intelligence's cost-per-admission figure.
    { to: '/financial-settings', label: 'Financial settings', icon: Settings2, product: Product.HospiceLink, minTier: Tier.Gold, allow: ADMIN_ONLY },
    { to: '/billing', label: 'Billing', icon: CreditCard, allow: ADMIN_ONLY },
    // Settings is admin/owner-only, PLUS CommunityLink's Owner/Investor (the
    // Max demo shows Settings under Administrator, Owner, AND Owner/Investor
    // — but NOT the Executive Director, who gets Reports but not Settings).
    { to: '/settings', label: 'Settings', icon: Plug, allow: [...ADMIN_ONLY, Role.OwnerInvestor] },
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
    // GRANTS_SECTION removed — the Grants domain (Funding/Applications/
    // Agreements) is not needed and will be removed/purged. See the commented
    // section definition above.
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
    COMMUNITYLINK_MAIN_EXTRA,
    // No RECORDS_SECTION (Contacts/Companies/Documents) — not present in any
    // of the 3 reference demos; explicitly removed per user request even
    // though HospiceLink keeps it (still shared code, just not composed in
    // here). Leads/Referral Sources are CommunityLink's own contact model.
    COMMUNITYLINK_SALES,
    COMMUNITYLINK_OPERATIONS,
    COMMUNITYLINK_FINANCIAL,
    COMMUNITYLINK_ACTIVITY,
    COMMUNITYLINK_ADMIN_SETTINGS,
    ADMIN_SECTION,
  ],
};

// Returns true when the user's current role + tier permit the item. Tier
// comparison is product-aware (CommunityLink orders tiers Pro<Gold<Max, unlike
// HospiceLink's Pro<Max<Gold), so the caller passes the active product.
//
/**
 * The stable identifier for one nav row — what a custom role stores to say "this tab
 * is visible" (custom_roles.navKeys).
 *
 * `<sectionId>:<to>` rather than the path alone, because a path alone is NOT unique:
 * Occupancy overview appears twice (two tier windows) and /outreach/mileage appears
 * in both the Sales and Activity groups under different labels. Keying on the path
 * would make one admin checkbox silently govern two rows in different sections.
 *
 * Derived rather than hand-written on every NavItem: 200-odd items would each need a
 * literal key and a mistyped one is invisible until a row goes missing. The tradeoff
 * is that MOVING an item between sections, or changing its path, invalidates stored
 * keys — that row then stops appearing for custom roles until the admin re-checks it,
 * which is visible and recoverable rather than a silent permission change.
 */
export const navItemKey = (sectionId: string, item: NavItem): string =>
  `${sectionId}:${item.to}`;

export function isNavItemVisible(
  item: NavItem,
  product: Product,
  role: Role | null,
  tier: Tier,
  /**
   * A custom role's chosen tabs (`navItemKey` values), or undefined for a user
   * holding a plain role.
   *
   * Applied AFTER the product, role and tier rules — never instead of them — and
   * that ordering is what makes a custom role a pure NARROWING. An admin who checks
   * a tab their chosen base role cannot see, or that the tenant's tier does not
   * include, grants nothing: an earlier rule has already returned false. The worst a
   * mis-built custom role can do is show too FEW tabs.
   */
  allowedNavKeys?: readonly string[],
  /** The section this item is rendered in — see navItemKey for why it is needed. */
  sectionId?: string,
): boolean {
  // Product first. Until an item in a SHARED section needed to differ per
  // product (ADMIN_SECTION's "Admin"/"Team"), separation came entirely from
  // SECTIONS_BY_PRODUCT and this field was documentary — so a product-tagged
  // item in a shared section appeared under BOTH dashboards. For every item in a
  // product-specific section this check is a no-op, because the tag and the
  // section already agree.
  if (item.product && item.product !== product) return false;
  if (item.allow && !(role && item.allow.includes(role))) return false;
  if (item.minTier && !tierIncludes(product, tier, item.minTier)) return false;
  // maxTier is an upper bound: the item shows only up to (and including) that
  // tier. tierIncludes(maxTier, current) is true when current <= maxTier.
  if (item.maxTier && !tierIncludes(product, item.maxTier, tier)) return false;
  if (allowedNavKeys && sectionId !== undefined) {
    return allowedNavKeys.includes(navItemKey(sectionId, item));
  }
  return true;
}
