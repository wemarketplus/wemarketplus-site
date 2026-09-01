import type { ComponentType } from 'react';

export interface DashboardStatCard {
  id: string;
  label: string;
  value: string;
  hint?: string;
  tone?: 'primary' | 'azure' | 'amber' | 'success' | 'warning' | 'destructive';
  // Lucide glyph shown in the tinted chip at the tile's top-right, per the
  // reference design. Optional so a tile can render without one.
  icon?: ComponentType<{ className?: string }>;
  /**
   * Where the tile drills into. Optional: a tile with no destination renders as
   * plain text rather than a dead link.
   *
   * Exists for the Executive Dashboard, whose whole purpose is "see the whole
   * community at a glance" and then go to the thing that needs you — every tile in
   * the client's reference design is clickable. Only ever set to a route the
   * viewing role can actually open; a tile that bounces the user home is worse
   * than one that does nothing.
   */
  to?: string;
}

export interface DashboardActivityItem {
  id: string;
  title: string;
  detail: string;
  /** Display name of the user who did it; "System" for system-written rows. */
  actorName: string;
  actorEmail: string | null;
  // ISO date — rendered as both an absolute date/time and a relative age.
  occurredAt: string;
}

// Live tenant KPI summary — wemarketplus-backend/src/dashboard
// (DashboardSummaryDto from GET /dashboard/summary). Tenant-scoped aggregate
// assembled from prospects/tasks/revenue/notifications/audit.
/**
 * CommunityLink's own counts, from cl_leads / cl_tours — mirrors the backend
 * DashboardCommunityLinkDto. Absent for a tenant with no CommunityLink
 * entitlement, which is why every consumer must handle undefined.
 */
/**
 * The operations half of the Executive Director's dashboard. Mirrors the backend
 * DashboardOperationsDto.
 *
 * ABSENT below CommunityLink Gold, where there are no apartments and no work
 * orders. Its absence is the signal to fall back to the sales tiles — see
 * dashboardMapper.
 */
export interface DashboardOperations {
  /** Whole percent, server-rounded: occupied + reserved over total units. */
  occupancyRate: number;
  units: {
    total: number;
    occupied: number;
    available: number;
    reserved: number;
    waitlisted: number;
    onNotice: number;
    makeReady: number;
    maintenance: number;
    offline: number;
  };
  openWorkOrders: number;
  urgentWorkOrders: number;
  openMakeReadyTasks: number;
}

/**
 * The Owner/Investor's money figures. Mirrors the backend DashboardPortfolioDto.
 *
 * ABSENT for any viewer outside CL_FINANCIAL_ROLES — the server omits it rather
 * than trusting the client to hide it, so a non-financial role never receives the
 * tenant's rent roll or fee liability at all. Present at every CommunityLink tier,
 * unlike `operations`: the guide puts Monthly Revenue and Pending Referral Fees in
 * the owner's top row unconditionally and gates only the deeper financial modules
 * to larger plans.
 */
export interface DashboardPortfolio {
  /** Contracted monthly rent across occupied + reserved units. */
  rentRoll: { total: number; units: number };
  /** Ledger revenue booked in the current calendar month, against budget. */
  monthlyRevenue: { total: number; budgeted: number; entries: number };
  /** Referral fees at `pending` — owed, not yet settled. */
  pendingReferralFees: { total: number; count: number };
  /** Unresolved leakage items, by tracked monthly impact. */
  leakage: { monthlyImpact: number; count: number };
  /** Rent forgone on `available` units, from each unit's own rate. */
  vacancy: { monthlyLoss: number; units: number };
  /** Paid vs organic referral mix; organic is fee status `na`. */
  referralMix: {
    paid: number;
    organic: number;
    total: number;
    paidPercent: number;
  };
}

export interface DashboardCommunityLink {
  leads: {
    total: number;
    active: number;
    hot: number;
    byStage: Record<string, number>;
  };
  tours: {
    scheduled: number;
  };
  operations?: DashboardOperations;
  portfolio?: DashboardPortfolio;
  care?: DashboardCare;
}

/**
 * The Nurse/Caregiver's own assigned care tasks. Mirrors the backend
 * DashboardCareDto.
 *
 * SELF-SCOPED — every count is the acting user's own work, filtered server-side by
 * `assignedTo`. Absent for every non-care role.
 *
 * There is no wellness-check count here on purpose: the Resident Care Log that would
 * record one is still being built (the nav announces it as coming), and no existing
 * table holds a wellness check to count.
 */
export interface DashboardCare {
  tasks: {
    assigned: number;
    dueToday: number;
    overdue: number;
    undated: number;
  };
}

export interface DashboardSummary {
  product: string;
  communitylink?: DashboardCommunityLink;
  prospects: {
    total: number;
    byStage: Record<string, number>;
  };
  tasks: {
    open: number;
  };
  invoices: {
    overdue: number;
    outstanding: number;
  };
  notifications: {
    unread: number;
  };
  recentActivity: DashboardSummaryActivity[];
}

export interface DashboardSummaryActivity {
  id: string;
  action: string;
  resource: string | null;
  resourceId: string | null;
  actorName: string;
  actorEmail: string | null;
  // ISO date.
  createdAt: string;
}

// UI state — reserved for future toggles (date range, segment).
export interface DashboardUiState {
  _placeholder: true;
}

/** Mirrors the backend GoalMetric — what a dashboard tile counts. */
export type DashboardMetric = 'visits' | 'calls' | 'referrals';

export interface MetricProgress {
  metric: DashboardMetric;
  achieved: number;
  /** The user's own weekly target, or null when they have not set one. */
  target: number | null;
}

export type HotAlertReason = 'overdue_work' | 'flagged_hot';

export interface HotAlert {
  prospectId: string;
  patientName: string;
  stage: string;
  facilityName: string | null;
  aiAdmitScore: number | null;
  reason: HotAlertReason;
  detail: string;
}

/** GET /dashboard/my-day — the marketer's own pacing and today's urgent work. */
export interface MyDay {
  goals: MetricProgress[];
  hotAlerts: HotAlert[];
}
