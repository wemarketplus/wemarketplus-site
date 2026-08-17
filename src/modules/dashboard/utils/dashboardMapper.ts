// Lucide is the icon system the reference design uses (24px grid, 2px stroke).
import {
  Banknote,
  CalendarCheck,
  ClipboardList,
  DoorOpen,
  Flame,
  Inbox,
  ListChecks,
  LogOut,
  MoveRight,
  PieChart,
  Receipt,
  Sparkles,
  UserCheck,
  Users,
  Wrench,
} from 'lucide-react';
import { Product } from '@/shared/types';
import {
  CL_LEAD_STAGE,
  CL_URGENCY,
} from '@/modules/cl-leads/constants/clLeadApiConstants';
// The USD formatter the Financial Ledger, Revenue Leakage and Paid Referral tables
// already use, imported the same cross-module way cl-referrals does. The owner's
// tiles and the screens they link into must render money identically.
import { formatUsd } from '@/modules/cl-financial/utils/financialFormat';
import type {
  DashboardActivityItem,
  DashboardCare,
  DashboardOperations,
  DashboardPortfolio,
  DashboardStatCard,
  DashboardSummary,
} from '../types/dashboardTypes';

// Maps the live tenant summary (GET /dashboard/summary) onto the product-specific
// KPI tiles the dashboard already renders. Keeps the same four-tile layout but
// feeds real, tenant-scoped numbers. Stage keys mirror the backend ProspectStage
// enum (wemarketplus-backend/src/prospects/prospects.constants).
function stage(summary: DashboardSummary, key: string): number {
  return summary.prospects.byStage[key] ?? 0;
}

/**
 * The tiles read CANONICAL stages.
 *
 * They previously counted `inquiry`, `pending` and `evaluation` — all three of
 * which are LEGACY stages that `moveStage` rejects as targets and that nothing
 * in the current flow writes. Both tiles therefore read 0 for every tenant on
 * the current pipeline, permanently, which looks like an empty pipeline rather
 * than a broken tile.
 */
function hospicelinkStats(summary: DashboardSummary): DashboardStatCard[] {
  return [
    {
      id: 'new-referrals',
      label: 'New referrals',
      icon: Inbox,
      value: String(stage(summary, 'new_referral')),
      hint: 'Awaiting eligibility check',
      tone: 'primary',
    },
    {
      id: 'in-progress',
      label: 'Working',
      icon: ClipboardList,
      // The three middle stages of the admit pipeline — everything that is
      // being actively worked but not yet closed either way.
      value: String(
        stage(summary, 'eligibility') +
          stage(summary, 'face_to_face') +
          stage(summary, 'consent_order'),
      ),
      hint: `${summary.tasks.open} open task${summary.tasks.open === 1 ? '' : 's'}`,
      tone: 'warning',
    },
    {
      id: 'admitted',
      label: 'Admitted',
      icon: UserCheck,
      value: String(stage(summary, 'admitted')),
      hint: `${summary.prospects.total} total`,
      tone: 'success',
    },
    {
      id: 'overdue-invoices',
      label: 'Overdue invoices',
      icon: Receipt,
      value: String(summary.invoices.overdue),
      hint: summary.invoices.overdue > 0 ? 'Action needed' : 'All current',
      tone: summary.invoices.overdue > 0 ? 'destructive' : 'success',
    },
  ];
}

/**
 * The Sales Dashboard tiles the CommunityLink guide names: "Active Leads, Hot
 * Leads, and Tours Scheduled — check the Hot Leads list first, since those need
 * attention today."
 *
 * READS `summary.communitylink`, NOT `summary.prospects`. These four tiles used to
 * count the HospiceLink `prospects` table, which holds no CommunityLink rows —
 * and three of them read the stages `inquiry`, `evaluation` and `pending`, which
 * the HospiceLink tiles' own comment identifies as legacy values nothing writes.
 * So on a CommunityLink tenant every tile was structurally zero: not a slow
 * quarter, a query against the wrong table.
 *
 * `communitylink` is absent for a tenant with no CommunityLink entitlement. Since
 * every signed-in user can open either dashboard, that case is reachable — it
 * falls back to zeroes with a hint saying so, rather than to the prospect counts,
 * which would put another product's numbers under CommunityLink labels.
 */
function communitylinkStats(summary: DashboardSummary): DashboardStatCard[] {
  const cl = summary.communitylink;
  const notEntitled = cl === undefined;
  const leads = cl?.leads;
  const hot = leads?.hot ?? 0;
  return [
    {
      id: 'leads',
      label: 'Active leads',
      icon: Users,
      value: String(leads?.active ?? 0),
      hint: notEntitled
        ? 'No CommunityLink plan on this account'
        : `${leads?.total ?? 0} total`,
      tone: 'primary',
      // Every other CommunityLink tile set links; these four did not, so the
      // marketer's own dashboard was the one screen in the product whose numbers
      // went nowhere. All four destinations are CL_SALES_ROLES, which is exactly
      // who sees this set.
      to: notEntitled ? undefined : '/leads',
    },
    {
      id: 'hot-leads',
      label: 'Hot leads',
      icon: Flame,
      value: String(hot),
      hint: hot > 0 ? 'Needs attention today' : 'Nothing urgent',
      // The one tile the guide tells a marketer to open first, so it earns an
      // alarm colour when it is non-zero and a calm one when it is not.
      tone: hot > 0 ? 'destructive' : 'success',
      /**
       * "check the Hot Leads list first" — this is that list. The pipeline's
       * urgency filter reads its initial value from the query string, so the tile
       * opens Lead Pipeline already narrowed to hot leads rather than dropping the
       * reader into the full book to filter it themselves.
       */
      to: notEntitled ? undefined : `/leads?urgency=${CL_URGENCY.Hot}`,
    },
    {
      id: 'tours',
      label: 'Tours scheduled',
      icon: CalendarCheck,
      value: String(cl?.tours.scheduled ?? 0),
      hint: `${summary.tasks.open} open task${summary.tasks.open === 1 ? '' : 's'}`,
      tone: 'warning',
      to: notEntitled ? undefined : '/tours',
    },
    {
      id: 'move-ins',
      label: 'Move-ins',
      icon: MoveRight,
      value: String(leads?.byStage.moved_in ?? 0),
      hint: 'Moved-in stage',
      tone: 'success',
      to: notEntitled ? undefined : `/leads?stage=${CL_LEAD_STAGE.MovedIn}`,
    },
  ];
}

/**
 * The Executive Director's six tiles, verbatim from the client's guide: "Occupancy
 * %, Available Units, Make-Ready count, On-Notice residents, Hot Leads, and Open
 * Work Orders — all in one screen."
 *
 * SALES AND OPERATIONS TOGETHER, which is the whole point of the role ("Your view
 * combines sales and operations so you can see the whole community at a glance").
 * Four of the six are operations figures no other CommunityLink dashboard shows,
 * and Hot Leads is carried over from the sales set so the director does not have
 * to switch screens to see whether the pipeline needs them today.
 *
 * Every tile links to the module it summarises — each one is a question ("how many
 * units are turning over?") whose answer is a screen. Only called when
 * `operations` is present, so all six destinations are unlocked.
 */
function communitylinkExecutiveStats(
  summary: DashboardSummary,
  operations: DashboardOperations,
): DashboardStatCard[] {
  const { units, occupancyRate, openWorkOrders, urgentWorkOrders } = operations;
  const hot = summary.communitylink?.leads.hot ?? 0;
  return [
    {
      id: 'occupancy',
      label: 'Occupancy',
      icon: PieChart,
      value: `${occupancyRate}%`,
      hint: `${units.occupied + units.reserved} of ${units.total} units`,
      // 85% is the threshold the Occupancy summary report already uses to decide
      // green vs amber; the two must not disagree on the same screen.
      tone: occupancyRate >= 85 ? 'success' : 'warning',
      to: '/occupancy-overview',
    },
    {
      id: 'available-units',
      label: 'Available units',
      icon: DoorOpen,
      value: String(units.available),
      hint: 'Ready to show',
      tone: 'success',
      to: '/operations/inventory',
    },
    {
      id: 'make-ready',
      label: 'Make-ready',
      icon: ClipboardList,
      value: String(units.makeReady),
      hint: `${operations.openMakeReadyTasks} open task${operations.openMakeReadyTasks === 1 ? '' : 's'}`,
      tone: units.makeReady > 0 ? 'warning' : 'success',
      to: '/operations/make-ready',
    },
    {
      id: 'on-notice',
      label: 'On notice',
      icon: LogOut,
      value: String(units.onNotice),
      hint: units.onNotice > 0 ? 'Moving out soon' : 'None moving out',
      tone: units.onNotice > 0 ? 'destructive' : 'success',
      to: '/operations/inventory',
    },
    {
      id: 'hot-leads',
      label: 'Hot leads',
      icon: Flame,
      value: String(hot),
      hint: hot > 0 ? 'Needs attention today' : 'Nothing urgent',
      tone: hot > 0 ? 'destructive' : 'success',
      to: '/leads',
    },
    {
      id: 'open-work-orders',
      label: 'Open work orders',
      icon: Wrench,
      value: String(openWorkOrders),
      hint:
        urgentWorkOrders > 0
          ? `${urgentWorkOrders} urgent`
          : openWorkOrders > 0
            ? 'None urgent'
            : 'All clear',
      tone: urgentWorkOrders > 0 ? 'destructive' : openWorkOrders > 0 ? 'warning' : 'success',
      to: '/operations/maintenance',
    },
  ];
}

/**
 * The Nurse/Caregiver tiles: "Your Dashboard will be scoped to resident wellness
 * checks and your assigned care tasks."
 *
 * ASSIGNED CARE TASKS ONLY — the wellness-check half of that sentence has no data
 * behind it yet. The Resident Care Log that would record a wellness check is still
 * being built (it is announced in the sidebar as a `comingSoon` row), and no existing
 * table holds one. A fabricated "wellness checks today" tile on a clinician's home
 * screen would be the worst possible place to guess.
 *
 * REPLACES THE SALES TILES, which is the point. A Nurse on a CommunityLink tenant
 * previously fell through to `communitylinkStats` and got Active Leads, Hot Leads,
 * Tours Scheduled and Move-ins — four tenant-wide sales figures for a floor nurse,
 * every one of them a screen their role cannot open.
 *
 * The three counts are the caller's OWN, server-scoped by `assignedTo`. All four
 * tiles link to Tasks, which is where every one of them is actioned — the guide's
 * step 4, "use Tasks for medication reminders and check-in rounds".
 */
function communitylinkCareStats(care: DashboardCare): DashboardStatCard[] {
  const { assigned, dueToday, overdue, undated } = care.tasks;
  return [
    {
      id: 'care-tasks',
      label: 'My care tasks',
      icon: ClipboardList,
      value: String(assigned),
      hint: assigned > 0 ? 'Assigned to you' : 'Nothing assigned',
      tone: 'primary',
      to: '/tasks',
    },
    {
      id: 'care-due-today',
      label: 'Due today',
      icon: CalendarCheck,
      value: String(dueToday),
      hint: dueToday > 0 ? 'Medication and check-in rounds' : 'Nothing due today',
      tone: dueToday > 0 ? 'warning' : 'success',
      to: '/tasks',
    },
    {
      id: 'care-overdue',
      label: 'Overdue',
      icon: Flame,
      value: String(overdue),
      hint: overdue > 0 ? 'Past its due date' : 'Nothing late',
      tone: overdue > 0 ? 'destructive' : 'success',
      to: '/tasks',
    },
    {
      id: 'care-undated',
      label: 'No due date',
      icon: Inbox,
      value: String(undated),
      // Undated work is deliberately NOT called late — nobody ever said when it was
      // due — but it is still the nurse's to schedule, so it earns a tile.
      hint: undated > 0 ? 'Needs a date' : 'All dated',
      tone: undated > 0 ? 'warning' : 'success',
      to: '/tasks',
    },
  ];
}

/**
 * The Owner/Investor's six tiles, verbatim from the client's guide: "Occupancy
 * Rate, Available Units, Monthly Revenue, Pending Referral Fees, Hot Leads, and
 * Open Work Orders."
 *
 * FINANCE-FIRST, which is what separates this from the Executive set. The director
 * gets Make-Ready and On-Notice — the operational churn they personally clear; the
 * owner gets Monthly Revenue and Pending Referral Fees in those two slots, because
 * an investor is asking what the portfolio earned, not which units are being
 * turned. Occupancy, Available Units, Hot Leads and Open Work Orders appear on both
 * and read identically, from the same server figures.
 *
 * `operations` MAY BE ABSENT (below CL Gold, where the tenant has no apartment or
 * maintenance modules). The three tiles sourced from it degrade to a "not on this
 * plan" hint rather than a bare 0, and drop their links — a 0 with no explanation
 * reads as an empty community, and a link into a module the tenant cannot open is
 * worse than no link. The three financial tiles always have real numbers.
 *
 * Maintenance is the one tile whose destination the owner may not be able to open:
 * the guide is explicit that they want "a quick read on open tickets, without
 * needing to manage them yourself", so it links to the read-only maintenance view
 * when that is all their role has. `CL_MANAGEMENT_ROLES` covers OwnerInvestor on
 * `/operations/maintenance`, so the direct link is correct here.
 */
function communitylinkPortfolioStats(
  summary: DashboardSummary,
  portfolio: DashboardPortfolio,
  operations: DashboardOperations | undefined,
  canOpenFinancials: boolean,
  canOpenOccupancy: boolean,
): DashboardStatCard[] {
  const hot = summary.communitylink?.leads.hot ?? 0;
  const { pendingReferralFees, monthlyRevenue } = portfolio;
  // Below CL Gold there is no inventory or maintenance module behind these three.
  const noOps = operations === undefined;
  const opsHint = 'Not on this plan';

  return [
    {
      id: 'occupancy',
      label: 'Occupancy rate',
      icon: PieChart,
      value: noOps ? '—' : `${operations.occupancyRate}%`,
      hint: noOps
        ? opsHint
        : `${operations.units.occupied + operations.units.reserved} of ${operations.units.total} units`,
      // 85% is the threshold the Occupancy summary report uses for green vs amber;
      // the two must not disagree on the same screen.
      tone: noOps || operations.occupancyRate >= 85 ? 'success' : 'warning',
      // Occupancy Overview's Gold tier window admits only SuperAdmin and Director;
      // the owner reaches it at Max. Linking on plan alone bounced a Gold owner
      // back to "/" from a tile that had rendered a real number.
      to: noOps || !canOpenOccupancy ? undefined : '/occupancy-overview',
    },
    {
      id: 'available-units',
      label: 'Available units',
      icon: DoorOpen,
      value: noOps ? '—' : String(operations.units.available),
      hint: noOps ? opsHint : 'Ready to show',
      tone: 'success',
      to: noOps ? undefined : '/operations/inventory',
    },
    {
      id: 'monthly-revenue',
      label: 'Monthly revenue',
      icon: Banknote,
      // AN EMPTY LEDGER MONTH IS NOT A ZERO-REVENUE MONTH, and the two must not
      // look alike. Nothing posted yet shows "—" with a hint saying so; a real
      // $0 would be an extraordinary claim to make in green on an owner's screen.
      // Caught in testing against a tenant whose ledger stopped six months back:
      // the tile read "$0 · Booked this month" in success green, which says the
      // portfolio earned nothing rather than that nobody has posted August yet.
      value:
        monthlyRevenue.entries > 0 ? formatUsd(monthlyRevenue.total) : '—',
      // Budget is only meaningful once somebody has set one; otherwise say what
      // the figure IS rather than comparing it to zero and calling it 100% over.
      hint:
        monthlyRevenue.entries === 0
          ? 'Nothing posted this month'
          : monthlyRevenue.budgeted > 0
            ? `${formatUsd(monthlyRevenue.budgeted)} budgeted`
            : 'Booked this month',
      tone:
        monthlyRevenue.entries === 0
          ? 'primary'
          : monthlyRevenue.budgeted > 0 &&
              monthlyRevenue.total < monthlyRevenue.budgeted
            ? 'warning'
            : 'success',
      // Tier-aware, like the card button beside it. The Financial Ledger is CL
      // Max; linking unconditionally sent a Pro or Gold owner to /billing from a
      // tile that looked like a drill-down, while the card's own "Ledger" button
      // was correctly hidden on the same screen.
      to: canOpenFinancials ? '/financial/ledger' : undefined,
    },
    {
      id: 'pending-referral-fees',
      label: 'Pending referral fees',
      icon: Receipt,
      value: formatUsd(pendingReferralFees.total),
      hint:
        pendingReferralFees.count > 0
          ? `${pendingReferralFees.count} referral${pendingReferralFees.count === 1 ? '' : 's'} on move-in`
          : 'Nothing outstanding',
      // Amber, not red: an unpaid referral fee is a scheduled cost of a move-in
      // that is happening, not a failure. Red is for work nobody is doing.
      tone: pendingReferralFees.total > 0 ? 'warning' : 'success',
      to: '/paid-referrals',
    },
    {
      id: 'hot-leads',
      label: 'Hot leads',
      icon: Flame,
      value: String(hot),
      hint: hot > 0 ? 'Needs attention today' : 'Nothing urgent',
      tone: hot > 0 ? 'destructive' : 'success',
      to: '/leads',
    },
    {
      id: 'open-work-orders',
      label: 'Open work orders',
      icon: Wrench,
      value: noOps ? '—' : String(operations.openWorkOrders),
      hint: noOps
        ? opsHint
        : operations.urgentWorkOrders > 0
          ? `${operations.urgentWorkOrders} urgent`
          : operations.openWorkOrders > 0
            ? 'None urgent'
            : 'All clear',
      tone: noOps
        ? 'success'
        : operations.urgentWorkOrders > 0
          ? 'destructive'
          : operations.openWorkOrders > 0
            ? 'warning'
            : 'success',
      to: noOps ? undefined : '/operations/maintenance',
    },
  ];
}

/**
 * Which CommunityLink tile set to render.
 *
 * The executive set needs BOTH halves to be true: a role that owns the community
 * (management — the Executive Director, and the admin/owner tier above them) AND a
 * tenant whose plan includes operations. `operations` being present already proves
 * the second, so `isExecutive` carries only the role question.
 *
 * A sales persona keeps the sales tiles even on a Gold tenant: a Marketer cannot
 * open Apartment Inventory or Maintenance, so four of the six tiles would be
 * numbers they can look at and never act on.
 */
/** The counts a field technician's dashboard reads, from GET /cl/field-queue. */
export interface FieldQueueCounts {
  totalItems: number;
  makeReadyTasks: number;
  housekeepingTasks: number;
  maintenanceTickets: number;
}

/**
 * The field technician's tiles — Maintenance and Housekeeping.
 *
 * Their landing screen used to be the tenant SALES roll-up: Active leads, Hot
 * leads, Tours scheduled, Move-ins. Four numbers about a part of the business a
 * cleaner has no route into — /leads and /tours are CL_SALES_ROLES on the nav, the
 * route and the API alike. The guide opens by saying their view is "kept simple —
 * just your cleaning assignments", and step 1 sends them to My Queue.
 *
 * So these tiles answer "what do I owe", not "how is the community selling", and
 * every one links to a screen the role can actually open. The section counts are
 * already role-scoped by the server (it omits tickets for Housekeeping and
 * housekeeping tasks for Maintenance), so a tile only appears when that person
 * genuinely works that board.
 */
function communitylinkFieldStats(
  queue: FieldQueueCounts,
  operations: DashboardOperations | undefined,
  worksHousekeeping: boolean,
  worksTickets: boolean,
): DashboardStatCard[] {
  const tiles: DashboardStatCard[] = [
    {
      id: 'assigned-to-me',
      label: 'Assigned to me',
      icon: ListChecks,
      value: String(queue.totalItems),
      hint: queue.totalItems > 0 ? 'Due today or overdue' : 'You are clear',
      tone: queue.totalItems > 0 ? 'warning' : 'success',
      to: '/my-queue',
    },
  ];

  /**
   * ROLE-BASED, not count-based. This used to read
   * `housekeepingTasks > 0 || maintenanceTickets === 0`, which showed a
   * Maintenance technician a "My cleaning tasks" tile linking to
   * /operations/housekeeping — a screen blocked for them at the nav, the route and
   * the API — every time their ticket count was zero. Since nothing could assign a
   * ticket until this pass, that was always. The server already scopes the queue by
   * role; the tiles now follow the same fact.
   */
  if (worksHousekeeping) {
    tiles.push({
      id: 'my-cleaning',
      label: 'My cleaning tasks',
      icon: Sparkles,
      value: String(queue.housekeepingTasks),
      hint: 'Assigned and due',
      tone: queue.housekeepingTasks > 0 ? 'warning' : 'success',
      to: '/operations/housekeeping',
    });
  }
  if (worksTickets) {
    tiles.push({
      id: 'my-tickets',
      label: 'My work orders',
      icon: Wrench,
      value: String(queue.maintenanceTickets),
      hint: 'Open and assigned to you',
      tone: queue.maintenanceTickets > 0 ? 'destructive' : 'success',
      to: '/operations/maintenance',
    });
  }

  tiles.push({
    id: 'my-make-ready',
    label: 'My make-ready tasks',
    icon: ClipboardList,
    value: String(queue.makeReadyTasks),
    hint: operations
      ? `${operations.units.makeReady} unit${operations.units.makeReady === 1 ? '' : 's'} in turnover`
      : 'Units being prepped',
    tone: queue.makeReadyTasks > 0 ? 'warning' : 'success',
    to: '/operations/make-ready',
  });

  return tiles;
}

/**
 * What a CommunityLink FIELD or CARE persona sees when their plan does not include
 * the modules their dashboard is made of.
 *
 * Exists because the alternative was worse than an empty screen: with no
 * `fieldQueue` the mapper fell through to `communitylinkStats`, so a CL Pro
 * housekeeper or maintenance technician opened the app to Active Leads, Hot Leads,
 * Tours Scheduled and Move-ins — four tenant sales figures whose every destination
 * (/leads, /tours) their role is barred from at the nav, the route AND the API.
 * That is the exact defect the field branch was written to fix; it was fixed for
 * Gold and Max and left in place for Pro.
 *
 * One honest tile beats four dead ones. No `to`: there is nothing to open.
 */
function communitylinkNoPlanStats(): DashboardStatCard[] {
  return [
    {
      id: 'no-operations-plan',
      label: 'Your work',
      icon: ListChecks,
      value: '—',
      hint: 'Work orders and cleaning tasks are included with the Gold plan.',
      tone: 'primary',
    },
  ];
}

export function mapSummaryToStats(
  summary: DashboardSummary,
  product: Product,
  isExecutive = false,
  isPortfolio = false,
  isCare = false,
  fieldQueue?: FieldQueueCounts,
  isField = false,
  /** Which boards this role actually works — decides which field tiles render. */
  worksHousekeeping = false,
  worksTickets = false,
  /** CL Max — the tier the Financial Ledger / Revenue Leakage routes require. */
  canOpenFinancials = false,
  /** Whether this role+tier combination may open Occupancy Overview. */
  canOpenOccupancy = false,
): DashboardStatCard[] {
  if (product !== Product.CommunityLink) return hospicelinkStats(summary);
  const operations = summary.communitylink?.operations;
  const portfolio = summary.communitylink?.portfolio;
  const care = summary.communitylink?.care;

  /**
   * FIELD ROLES ARE CHECKED FIRST, for the same reason care is: Maintenance and
   * Housekeeping belong to no CommunityLink group that reaches the sales tiles, so
   * falling through to them showed a cleaner four numbers about leads, tours and
   * move-ins — a part of the business they cannot open a single screen of. Their
   * guide says the opposite in its first line: "your view is kept simple — just
   * your cleaning assignments."
   *
   * `fieldQueue` rather than the summary: what a technician owes is per-USER, and
   * /dashboard/summary is a tenant roll-up with no notion of "mine".
   */
  if (fieldQueue) {
    return communitylinkFieldStats(
      fieldQueue,
      operations,
      worksHousekeeping,
      worksTickets,
    );
  }
  /**
   * A field role whose plan has no operations bundle. Checked immediately after
   * the queue so the sales fall-through below can never be reached by a persona
   * that cannot open a single sales screen — see communitylinkNoPlanStats.
   */
  if (isField) {
    return communitylinkNoPlanStats();
  }
  /**
   * CARE IS CHECKED FIRST and shares no membership with the others: Nurse and
   * Caregiver are in no CommunityLink group that reaches the sales, executive or
   * financial tiles, so this is a clean branch rather than a precedence question.
   * It comes first because falling through to the sales tiles is precisely the bug
   * this replaces.
   */
  if (isCare) {
    // Same rule as the field roles: a care persona reaches no sales screen, so an
    // absent care block must not fall through to the sales tiles.
    return care ? communitylinkCareStats(care) : communitylinkNoPlanStats();
  }
  /**
   * PORTFOLIO WINS OVER EXECUTIVE. `Role.OwnerInvestor` is a member of
   * CL_MANAGEMENT_ROLES, so it satisfies `isExecutive` too — without this ordering
   * an owner would land on the Executive Dashboard and never see the finance tiles
   * the guide opens with. The owner is the more specific persona, so it is checked
   * first.
   *
   * Unlike the executive set this does NOT require `operations`: the financial half
   * is available at every tier, and the three operations tiles degrade in place.
   */
  if (isPortfolio && portfolio) {
    return communitylinkPortfolioStats(
      summary,
      portfolio,
      operations,
      canOpenFinancials,
      canOpenOccupancy,
    );
  }
  return isExecutive && operations
    ? communitylinkExecutiveStats(summary, operations)
    : communitylinkStats(summary);
}

/**
 * Turns an audit action or resource into a readable label.
 *
 * Audit actions are stored SHOUTING ("MOVE_PIPELINE_STAGE"), so lowercase first —
 * otherwise the per-word capitalisation is a no-op and the feed shouts. Product
 * table prefixes (`hl_` HospiceLink, `cl_` CommunityLink) are stripped so
 * "hl_leads" reads as "Leads" rather than "Hl Leads".
 */
function titleize(value: string): string {
  return value
    .toLowerCase()
    .replace(/^(hl|cl)_/, '')
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (c) => c.toUpperCase())
    .trim();
}

export function mapSummaryToActivity(
  summary: DashboardSummary,
): DashboardActivityItem[] {
  return summary.recentActivity.map((entry) => {
    const resource = entry.resource ? titleize(entry.resource) : 'Record';
    return {
      id: entry.id,
      title: `${titleize(entry.action)} — ${resource}`,
      // The raw resource uuid was noise; the actor is the useful second line.
      detail: entry.actorName,
      actorName: entry.actorName,
      actorEmail: entry.actorEmail,
      occurredAt: entry.createdAt,
    };
  });
}
