import { Role } from '../types/permissionTypes';

// Human-readable labels for roles. Used in admin UIs (user list, role pickers).
export const ROLE_LABELS: Record<Role, string> = {
  [Role.SuperAdmin]: 'Super Admin',
  [Role.Admin]: 'Administrator',
  [Role.Owner]: 'Owner',
  [Role.Manager]: 'Manager',
  [Role.Marketer]: 'Marketer',
  [Role.Nurse]: 'Nurse',
  [Role.Caregiver]: 'Caregiver',
  [Role.Rep]: 'Sales Rep',
  [Role.Director]: 'Executive Director',
  [Role.SalesAdmissions]: 'Sales/Admissions',
  [Role.OwnerInvestor]: 'Owner/Investor',
  [Role.Maintenance]: 'Maintenance',
  [Role.Housekeeping]: 'Housekeeping',
};

// Convenience role groups for common gating decisions. Prefer naming a group
// here over inlining `['admin', 'manager']` at call sites — keeps intent
// readable and lets us re-tune the policy in one place.
export const STAFF_ROLES: readonly Role[] = [
  Role.SuperAdmin,
  Role.Admin,
  Role.Owner,
  Role.Manager,
];
export const ADMIN_ONLY: readonly Role[] = [Role.SuperAdmin, Role.Admin, Role.Owner];
// Platform-level surfaces (owner portal). The backend enforces the same
// gate — /owner/* returns 403 for tenant Admin/Owner.
export const SUPER_ADMIN_ONLY: readonly Role[] = [Role.SuperAdmin];

// --- HospiceLink role groups --------------------------------------------------
// HospiceLink had NO role groups: every module either used STAFF_ROLES or was
// ungated, so Marketer, Nurse and Caregiver all resolved to the same 42-item
// sidebar. Gold is sold as "4-role access: Admin, Marketer, Nurse, Caregiver", so
// the four personas need distinct views. These groups say which roles may SEE a
// class of module; the backend still enforces its own @Roles independently.

// Management oversight — same set as STAFF_ROLES, named separately so the
// HospiceLink policy can diverge from the generic one without a cascade.
export const HL_MANAGEMENT_ROLES: readonly Role[] = [...STAFF_ROLES];

// The marketing/sales surface: inbound leads, pipeline, referral sources, jobs,
// territories, scheduling. Deliberately EXCLUDES Nurse and Caregiver — this is
// where referral-source financials and account strategy live, and a caregiver has
// no reason to see which hospital is worth the most.
export const HL_MARKETING_ROLES: readonly Role[] = [
  ...HL_MANAGEMENT_ROLES,
  Role.Marketer,
  Role.Rep,
];

// Clinical group (family communication, secure messaging, admissions). Management
// plus the two clinical personas.
export const HL_CLINICAL_ROLES: readonly Role[] = [
  ...HL_MANAGEMENT_ROLES,
  Role.Nurse,
  Role.Caregiver,
];

// Field-work surfaces every persona uses: appointments, the follow-up calendar,
// notes, reminders, daily goals, the AI assistant, EVV and mileage. This is the
// widest HospiceLink group.
export const HL_FIELD_ROLES: readonly Role[] = [
  ...HL_MANAGEMENT_ROLES,
  Role.Marketer,
  Role.Rep,
  Role.Nurse,
  Role.Caregiver,
];

/**
 * Roles a management user may PREVIEW via the "viewing as" switcher. Only the
 * three field personas are listed: the switcher exists to check what a scoped user
 * sees, so previewing another management role would be pointless, and previewing
 * "up" must be impossible.
 *
 * The switcher only ever NARROWS the navigation. It never grants anything — every
 * API call still carries the real role in the JWT, so a previewing Admin who
 * reaches a hidden route still gets that route's real authorization answer.
 */
export const HL_VIEW_AS_ROLES: readonly Role[] = [
  Role.Marketer,
  Role.Nurse,
  Role.Caregiver,
];

// --- CommunityLink role groups (mirror the /demo/communitylink/* sidebars) ---
// Each group defines which roles may SEE a class of module. Field roles see the
// least; management roles see everything.

// Management: full oversight — admin, settings, reports, financial. Mirrors the
// demo's Administrator / Executive Director / Owner-Investor nav.
export const CL_MANAGEMENT_ROLES: readonly Role[] = [
  Role.SuperAdmin,
  Role.Admin,
  Role.Owner,
  Role.Director,
  Role.OwnerInvestor,
];

// Sales-and-outreach roles: the pipeline, tours, referrals, mileage, tasks — but
// NOT admin/settings/financial. Includes management (a superset) plus the
// sales-focused personas. Used to gate the Sales & outreach section.
export const CL_SALES_ROLES: readonly Role[] = [
  ...CL_MANAGEMENT_ROLES,
  Role.Manager,
  Role.Marketer,
  Role.SalesAdmissions,
];

// Financial section (ledger, revenue leakage, LOC, concessions): management plus
// Sales/Admissions, which the Max demo gives financial visibility. NOT the
// field roles. (Marketer/Manager do not get financials.)
export const CL_FINANCIAL_ROLES: readonly Role[] = [
  ...CL_MANAGEMENT_ROLES,
  Role.SalesAdmissions,
];

// Apartment inventory / occupancy: an ops-overview surface — management and
// Sales/Admissions. Field roles only get "Unit Status" as part of their own
// queue (handled per-item), so they are NOT in this group.
export const CL_INVENTORY_ROLES: readonly Role[] = [
  ...CL_MANAGEMENT_ROLES,
  Role.SalesAdmissions,
];

// Maintenance module (tickets): management + Sales/Admissions oversight + the
// Maintenance field role. Housekeeping does NOT see maintenance (except a
// read-only "Maintenance View" at Max, out of scope for nav-hiding here).
export const CL_MAINTENANCE_ROLES: readonly Role[] = [
  ...CL_MANAGEMENT_ROLES,
  Role.SalesAdmissions,
  Role.Maintenance,
];

// Housekeeping module: management + Sales/Admissions oversight + the
// Housekeeping field role. Maintenance does NOT see housekeeping.
export const CL_HOUSEKEEPING_ROLES: readonly Role[] = [
  ...CL_MANAGEMENT_ROLES,
  Role.SalesAdmissions,
  Role.Housekeeping,
];

// Make-ready board: the shared handoff surface — both field roles work it, plus
// management and Sales/Admissions oversight.
export const CL_MAKE_READY_ROLES: readonly Role[] = [
  ...CL_MANAGEMENT_ROLES,
  Role.SalesAdmissions,
  Role.Maintenance,
  Role.Housekeeping,
];

// Every CommunityLink role. Tasks is a cross-role surface — every role in the
// demo screenshots (including both field roles) has a "Tasks" sidebar item.
export const CL_ALL_ROLES: readonly Role[] = [
  ...CL_SALES_ROLES,
  Role.Maintenance,
  Role.Housekeeping,
];

// Read-only "Unit Status" surface (Max tier): apartment status visibility for
// the two field roles, who are NOT in CL_INVENTORY_ROLES (no inventory write
// access). Mirrors the backend's method-level @Roles() override on
// ClApartmentController's GET handlers.
export const CL_UNIT_STATUS_ROLES: readonly Role[] = [
  Role.Maintenance,
  Role.Housekeeping,
];

// Competitor intel (Max tier): Admin/Owner/Owner-Investor only — narrower than
// the rest of the Financial section. The Max demo does NOT give this to
// Executive Director or Sales/Admissions (unlike ledger/leakage/concessions/
// LOC, which both of those personas do get).
export const CL_COMPETITOR_INTEL_ROLES: readonly Role[] = [
  Role.SuperAdmin,
  Role.Admin,
  Role.Owner,
  Role.OwnerInvestor,
];

// Max-tier "field activity" surfaces (Mileage & Expenses, Gift & Gratuity):
// everyone with a sales/ops persona except Owner/Investor, who the Max demo
// does not give these to (Owner/Investor's Activity section is just Activity
// Notes, Tasks, and Aircall).
export const CL_FIELD_ACTIVITY_ROLES: readonly Role[] = [
  Role.SuperAdmin,
  Role.Admin,
  Role.Owner,
  Role.Director,
  Role.Manager,
  Role.Marketer,
  Role.SalesAdmissions,
];

// Read-only "Maintenance View" surface (Max tier): a nav/route item scoped to
// Housekeeping only — management/Sales-Admissions already have the full
// "Maintenance" item (CL_MAINTENANCE_ROLES) and don't need a duplicate
// read-only one. The underlying GET endpoint itself is opened more broadly
// (CL_MAKE_READY_ROLES, backend-side) since it's the same data as the
// Maintenance module — this constant is deliberately narrower and only for
// gating this distinct nav item/route.
export const CL_MAINTENANCE_VIEW_ROLES: readonly Role[] = [Role.Housekeeping];
