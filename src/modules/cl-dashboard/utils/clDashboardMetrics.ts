import {
  CL_LEAD_STAGE,
  CL_URGENCY,
  type ClLeadRecord,
  type ClLeadStage,
} from '@/modules/cl-leads';
import {
  APARTMENT_STATUS,
  HOUSEKEEPING_STATUS,
  MAINTENANCE_STATUS,
  MAKE_READY_STATUS,
  occupancyRate,
  toApartment,
  type ClApartmentRecord,
  type ClHousekeepingTaskRecord,
  type ClMaintenanceTicketRecord,
  type ClMakeReadyTaskRecord,
  type MaintenanceStatus,
} from '@/modules/cl-operations';
import { FEE_STATUS, type ClPaidReferralRecord } from '@/modules/cl-referrals';
import { CL_TOUR_STATUS, type ClTourRecord } from '@/modules/cl-tours';

/**
 * Every number the CommunityLink dashboards print, derived in one place.
 *
 * These are PURE functions over the records the cl/* list endpoints already
 * return — deliberately not a new `/cl/dashboard` API. The guide's four
 * dashboards (Sales, Executive, Portfolio, My Queue) count the same handful of
 * things in different combinations, and the tenant-wide aggregate each tile
 * wants is not an endpoint that exists. Deriving client-side keeps a tile and
 * the screen it links to reading the same rows, which is what stops "6 open
 * work orders" on the dashboard from disagreeing with the six the Maintenance
 * table shows.
 *
 * THE SAMPLING CAVEAT, stated once here because every caller inherits it: the
 * hooks fetch ONE page (CL_DASHBOARD_FETCH_LIMIT rows) per resource, so on a
 * tenant with more rows than that these are counts over the most recent page,
 * not the true tenant total. That is the same approximation
 * OccupancyOverviewPage has always made. Fixing it properly means server-side
 * aggregates; until then, do not present these figures as authoritative
 * financials, and prefer the paginated `total` wherever a plain count of an
 * unfiltered resource will do.
 */

/** One page per resource. Matches OccupancyOverviewPage's existing limit. */
export const CL_DASHBOARD_FETCH_LIMIT = 100;

// --- leads ----------------------------------------------------------------

/**
 * The stages a family is still being worked in — the guide's journey from
 * Inquiry through Decision Pending, before Move-In closes it.
 *
 * `moved_in`, `lost` and `inactive` are excluded on purpose: a moved-in family
 * is operations' business now, and counting them as "active leads" would make
 * the tile climb forever and never fall.
 */
export const CL_OPEN_LEAD_STAGES: readonly ClLeadStage[] = [
  CL_LEAD_STAGE.Inquiry,
  CL_LEAD_STAGE.Contacted,
  CL_LEAD_STAGE.TourScheduled,
  CL_LEAD_STAGE.Toured,
  CL_LEAD_STAGE.ProposalSent,
  CL_LEAD_STAGE.DepositPaid,
];

export const isOpenClLead = (lead: ClLeadRecord): boolean =>
  CL_OPEN_LEAD_STAGES.includes(lead.stage);

/** An open lead the marketer marked urgent. The guide's "Hot Leads". */
export const isHotClLead = (lead: ClLeadRecord): boolean =>
  isOpenClLead(lead) && lead.urgency === CL_URGENCY.Hot;

export const leadDisplayName = (lead: ClLeadRecord): string =>
  [lead.firstName, lead.lastName].filter(Boolean).join(' ').trim() ||
  'Unnamed lead';

/**
 * Hot leads, soonest follow-up first.
 *
 * A lead with NO follow-up date sorts last rather than first. It is tempting to
 * treat "no date" as maximally overdue, but the guide tells the marketer to work
 * this list top-down, and an untouched new inquiry with no date set is not more
 * urgent than one whose promised call-back was yesterday.
 */
export function hotClLeads(leads: readonly ClLeadRecord[]): ClLeadRecord[] {
  return leads.filter(isHotClLead).sort((a, b) => {
    if (a.followUpDate && b.followUpDate) {
      return a.followUpDate < b.followUpDate ? -1 : 1;
    }
    if (a.followUpDate) return -1;
    if (b.followUpDate) return 1;
    return a.createdAt < b.createdAt ? -1 : 1;
  });
}

// --- tours ----------------------------------------------------------------

/** Booked and still ahead of us — what "Tours Scheduled" means on the tile. */
export function upcomingClTours(
  tours: readonly ClTourRecord[],
  now: Date = new Date(),
): ClTourRecord[] {
  const from = now.getTime();
  return tours
    .filter(
      (tour) =>
        tour.status === CL_TOUR_STATUS.Scheduled &&
        new Date(tour.scheduledAt).getTime() >= from,
    )
    .sort((a, b) => (a.scheduledAt < b.scheduledAt ? -1 : 1));
}

// --- work orders ----------------------------------------------------------

/**
 * A ticket somebody still owes work on. `scheduled` counts as open: the work is
 * booked but not done, and a resident with a booked repair still has a leak.
 */
export const OPEN_MAINTENANCE_STATUSES: readonly MaintenanceStatus[] = [
  MAINTENANCE_STATUS.Open,
  MAINTENANCE_STATUS.InProgress,
  MAINTENANCE_STATUS.Scheduled,
];

export const isOpenClTicket = (ticket: ClMaintenanceTicketRecord): boolean =>
  OPEN_MAINTENANCE_STATUSES.includes(ticket.status);

export const isOpenClMakeReady = (task: ClMakeReadyTaskRecord): boolean =>
  task.status === MAKE_READY_STATUS.Pending ||
  task.status === MAKE_READY_STATUS.InProgress ||
  task.status === MAKE_READY_STATUS.Blocked;

export const isOpenClHousekeeping = (
  task: ClHousekeepingTaskRecord,
): boolean =>
  task.status === HOUSEKEEPING_STATUS.Pending ||
  task.status === HOUSEKEEPING_STATUS.InProgress;

// --- occupancy ------------------------------------------------------------

export interface ClOccupancySnapshot {
  total: number;
  occupied: number;
  available: number;
  reserved: number;
  makeReady: number;
  onNotice: number;
  maintenance: number;
  offline: number;
  /** 0–1. Reserved counts as filled — see the note below. */
  rate: number;
}

/**
 * The unit-status roll-up behind the Executive and Portfolio dashboards.
 *
 * `rate` delegates to cl-operations' own `occupancyRate` rather than
 * recomputing, so the dashboard tile and the Occupancy Overview screen can
 * never print different percentages for the same units. That function counts
 * RESERVED as filled (a deposit-paid unit is not sellable twice), which is the
 * established definition here — change it there, not here.
 */
export function clOccupancySnapshot(
  apartments: readonly ClApartmentRecord[],
): ClOccupancySnapshot {
  const count = (status: string) =>
    apartments.filter((a) => a.status === status).length;

  return {
    total: apartments.length,
    occupied: count(APARTMENT_STATUS.Occupied),
    available: count(APARTMENT_STATUS.Available),
    reserved: count(APARTMENT_STATUS.Reserved),
    makeReady: count(APARTMENT_STATUS.MakeReady),
    onNotice: count(APARTMENT_STATUS.OnNotice),
    maintenance: count(APARTMENT_STATUS.Maintenance),
    offline: count(APARTMENT_STATUS.Offline),
    rate: occupancyRate(apartments.map(toApartment)),
  };
}

// --- money ----------------------------------------------------------------

/**
 * Rent currently being collected: the monthly rate of every filled unit.
 *
 * Reserved units are NOT counted even though `occupancyRate` treats them as
 * filled. A reserved unit is promised, not paying, and the Owner/Investor tile
 * this feeds is labelled "Monthly Revenue" — booking revenue that has not
 * started is the kind of optimism a financial figure must not carry.
 */
export function clMonthlyRevenue(
  apartments: readonly ClApartmentRecord[],
): number {
  return apartments
    .filter((a) => a.status === APARTMENT_STATUS.Occupied)
    .reduce((sum, a) => sum + (a.monthlyRate ?? 0), 0);
}

export interface ClPendingFees {
  count: number;
  amount: number;
}

/** Referral invoices owed to paid sources (A Place for Mom, Caring.com, …). */
export function clPendingReferralFees(
  referrals: readonly ClPaidReferralRecord[],
): ClPendingFees {
  const pending = referrals.filter(
    (r) => r.feeStatus === FEE_STATUS.Pending,
  );
  return {
    count: pending.length,
    amount: pending.reduce((sum, r) => sum + (r.referralFee ?? 0), 0),
  };
}

/** "$12,400" — whole dollars, because cents are noise at dashboard scale. */
export function formatClCurrency(amount: number): string {
  return amount.toLocaleString(undefined, {
    style: 'currency',
    currency: 'USD',
    maximumFractionDigits: 0,
  });
}

/** "68%" from a 0–1 rate. */
export function formatClPercent(rate: number): string {
  return `${Math.round(rate * 100)}%`;
}
