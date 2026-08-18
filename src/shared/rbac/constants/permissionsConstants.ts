import { Role } from '../types/permissionTypes';

/**
 * What to CALL this person: their tenant-defined job title when they hold a custom
 * role, otherwise their role's standard label.
 *
 * One helper rather than `customRole?.name ?? ROLE_LABELS[role]` at each call site:
 * the header, the sidebar footer, the dashboard greeting and the users table must
 * agree, or a Volunteer Coordinator reads as "Caregiver" on some screens and not
 * others. Takes the two fields rather than a user object so it works for a
 * UserRecord row and for the authenticated user alike.
 */
export const roleTitle = (
  role: Role | null | undefined,
  customRoleName?: string | null,
): string => customRoleName?.trim() || (role ? ROLE_LABELS[role] : '');

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

// Clinical group (family communication, admissions). Management plus the two
// clinical personas.
//
// Secure messaging used to be listed here and is deliberately NOT: it is staff
// coordination, not patient care, and it sits on HL_FIELD_ROLES so a marketer who
// has just assigned a visit can talk to the nurse who has to make it. The chat
// backend applies no @Roles at all — only the Gold feature key — so the wider group
// cannot 403.
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

// NOTE: HL_VIEW_AS_ROLES / CL_VIEW_AS_ROLES / VIEW_AS_ROLES used to live here —
// the personas a management user could PREVIEW via the "viewing as" switcher. The
// switcher is gone: that row now reports the signed-in role and offers no others
// (see ViewingAsBadge), so no list of other people's roles is needed anywhere.

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

/**
 * The two CLINICAL CARE personas as they appear in CommunityLink — the roles a
 * community offering Assisted Living or Memory Care staffs its floors with.
 *
 * NEW TO COMMUNITYLINK. Nurse and Caregiver have existed as HospiceLink roles since
 * the beginning (see HL_CLINICAL_ROLES) but named in NO CommunityLink group at all,
 * which meant a Nurse signed into a CommunityLink tenant saw three ungated rows —
 * Dashboard, My profile, Notifications — and nothing else. The client's guide gives
 * them four working surfaces (Activity Notes, Tasks, Mileage & Expenses, and a
 * Resident Care Log that is still being built), so they need a group to be named in.
 *
 * DELIBERATELY NOT ADDED TO CL_SALES_ROLES, which would have been the one-line
 * change. That group gates the lead pipeline, tour scheduler, referral sources, the
 * paid referral portal, GPS check-in and the AI sales assistant — a floor nurse has
 * no business in a family's referral fee, and widening it would have handed them
 * fourteen screens to get the two the guide asks for.
 */
export const CL_CARE_ROLES: readonly Role[] = [Role.Nurse, Role.Caregiver];

// Every CommunityLink role. Tasks is a cross-role surface — every role in the
// demo screenshots (including both field roles) has a "Tasks" sidebar item, and
// the care personas use it for medication reminders and check-in rounds.
export const CL_ALL_ROLES: readonly Role[] = [
  ...CL_SALES_ROLES,
  Role.Maintenance,
  Role.Housekeeping,
  ...CL_CARE_ROLES,
];

/**
 * The cross-lead ACTIVITY NOTES log.
 *
 * `CL_SALES_ROLES` plus the care personas, because the guide routes a Nurse or
 * Caregiver here explicitly: the Resident Care Log is not built yet, and "until that's
 * ready, use Activity Notes as the closest available substitute". Its own group rather
 * than widening CL_SALES_ROLES — see CL_CARE_ROLES for why.
 */
export const CL_ACTIVITY_NOTES_ROLES: readonly Role[] = [
  ...CL_SALES_ROLES,
  ...CL_CARE_ROLES,
];

/**
 * The still-being-built RESIDENT CARE LOG — wellness checks, incident notes and
 * family updates tied to a resident.
 *
 * Care personas only, and rendered as a `comingSoon` row (inert, "Soon" badge) because
 * there is no resident entity to hang a care log off yet: `cl_apartments.residentName`
 * is a nullable varchar on a unit, not a record you can attach a wellness check to.
 * The row exists because the guide tells a nurse the tab is coming and names what will
 * be in it — announcing it inertly is honest, and shipping a link to a screen that
 * cannot store a care note would not be.
 */
export const CL_RESIDENT_CARE_ROLES: readonly Role[] = [...CL_CARE_ROLES];

// Read-only "Unit Status" surface (Max tier): apartment status visibility for
// the two field roles, who are NOT in CL_INVENTORY_ROLES (no inventory write
// access). Mirrors the backend's method-level @Roles() override on
// ClApartmentController's GET handlers.
export const CL_UNIT_STATUS_ROLES: readonly Role[] = [
  Role.Maintenance,
  Role.Housekeeping,
];

/**
 * The two CommunityLink FIELD personas — the people who work a queue of assigned
 * work orders rather than a book of leads.
 *
 * Holds the same two members as CL_UNIT_STATUS_ROLES today and is deliberately NOT
 * an alias of it: that constant exists because Unit Status is a read-only window
 * management does not need a duplicate of, this one because "is this person a field
 * technician" is a question about the person. Gates the "My Queue" nav row, which
 * management does not get — they have the Executive Dashboard, and their own work is
 * not assigned to them one ticket at a time.
 */
export const CL_FIELD_ROLES: readonly Role[] = [
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

/**
 * MILEAGE & EXPENSES on CommunityLink.
 *
 * `CL_FIELD_ACTIVITY_ROLES` plus the care personas. Its own constant because that
 * group gates TWO surfaces — Mileage and Gift & Gratuity — and the guide gives the
 * care roles only the first: "If your role involves traveling between communities or
 * in-home visits, log those trips in Mileage & Expenses the same way a Sales Marketer
 * does." It says nothing about gift and gratuity compliance logging, which is an
 * outreach-gifting surface, so widening the shared group would have granted a screen
 * nobody asked for.
 *
 * The ROUTE already admits them (`CALENDAR_ROLES` is a union that includes
 * `HL_FIELD_ROLES`, which has both care roles), and the backend mileage controller
 * carries no `@Roles` and self-scopes its list. So this nav row was the only thing
 * standing between a CommunityLink nurse and a screen already built for them.
 */
export const CL_MILEAGE_ROLES: readonly Role[] = [
  ...CL_FIELD_ACTIVITY_ROLES,
  ...CL_CARE_ROLES,
];

// Read-only "Maintenance View" surface (Max tier): a nav/route item scoped to
// Housekeeping only — management/Sales-Admissions already have the full
// "Maintenance" item (CL_MAINTENANCE_ROLES) and don't need a duplicate
// read-only one. The underlying GET endpoint itself is opened more broadly
// (CL_MAKE_READY_ROLES, backend-side) since it's the same data as the
// Maintenance module — this constant is deliberately narrower and only for
// gating this distinct nav item/route.
export const CL_MAINTENANCE_VIEW_ROLES: readonly Role[] = [Role.Housekeeping];

// --- Cross-product groups ---------------------------------------------------

/**
 * Roles that may open the SHARED TEAM CALENDAR and the MILEAGE screen — the two
 * surfaces that stopped being HospiceLink-only.
 *
 * Both are `HL_FIELD_ROLES` (who already had them) plus the CommunityLink sales
 * and management personas, which is exactly the union of the two products' field
 * groups. Written as a union rather than a hand-listed set so adding a role to
 * either product's group carries into both screens automatically — the failure
 * mode of a hand-listed set is a new persona silently losing its calendar.
 *
 * The backend agrees by carrying NO `@Roles` on the calendar and mileage handlers
 * at all (see appointments.controller.ts and mileage.controller.ts), so this list
 * is the narrower of the two sides — never the wider.
 */
export const CALENDAR_ROLES: readonly Role[] = [
  ...HL_FIELD_ROLES,
  ...CL_SALES_ROLES.filter((role) => !HL_FIELD_ROLES.includes(role)),
];
