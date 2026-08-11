import { Car, Route, UserCheck, Users } from 'lucide-react';
import { useGetTeamMileageSummaryQuery } from '@/modules/field';
import { StatTile } from '@/shared/ui/data-display';
import { useGetSeatUsageQuery } from '../api/usersApi';

/**
 * Reimbursement is money owed to a person, so it keeps its cents: rounding
 * $10.52 to "$11" on an admin screen invites someone to reconcile against a
 * figure the system never actually calculated.
 */
const currency = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});
/** Miles are recorded to one decimal, so display them that way (15.7, not 16). */
const miles = new Intl.NumberFormat('en-US', { maximumFractionDigits: 1 });
/** Whole counts (seats, trips). */
const number = new Intl.NumberFormat('en-US', { maximumFractionDigits: 0 });

/**
 * The Admin / Office Manager band on the Team page: seats allowed, seats used,
 * and team-wide mileage.
 *
 * Rendered only inside a RoleGate on UsersPage — both endpoints it calls are
 * Admin/Owner-only server-side, and a Manager (who MAY read the user list)
 * would otherwise fire two requests that 403 on every visit.
 *
 * Deliberately a band on the EXISTING Team screen rather than a new "Admin"
 * page. `/users` is already the team surface, already carries the invite flow,
 * and already sits in the ADMIN nav section — a second page would have split
 * "manage your team" across two routes for no reason.
 */
export function TeamOverviewStats() {
  const { data: seats, isLoading: seatsLoading } = useGetSeatUsageQuery();
  const { data: mileage, isLoading: mileageLoading } =
    useGetTeamMileageSummaryQuery();

  // A dash rather than a zero while loading: "0 seats used" is a claim, and a
  // wrong one that resolves a moment later reads as a glitch.
  const dash = '—';

  const seatsAllowed =
    seats?.allowed === null || seats?.allowed === undefined
      ? null
      : seats.allowed;

  const seatsHint = (): string => {
    if (seatsLoading || !seats) return 'Loading…';
    if (seatsAllowed === null) {
      // assertSeatAvailable fails open on an unrecognised plan, so there is
      // genuinely no cap to report — say so rather than implying unlimited.
      return 'No seat limit is configured for this plan.';
    }
    // Seats are billed ONCE per tenant against the subscription, not per product
    // dashboard — so a dual-product tenant viewing HospiceLink can legitimately
    // see a CommunityLink plan name here. Say "billing plan" so that reads as
    // intentional rather than as the wrong plan being shown.
    const plan = seats.planName ? `Billing plan: ${seats.planName}` : 'Your plan';
    return seats.enforced
      ? plan
      : `${plan} · limit not enforced in this environment`;
  };

  const usedHint = (): string => {
    if (seatsLoading || !seats) return 'Loading…';
    if (seats.remaining === null) return 'Active users in your workspace';
    if (seats.remaining === 0) {
      return 'All seats are in use — upgrade to add more users.';
    }
    return `${seats.remaining} seat${seats.remaining === 1 ? '' : 's'} remaining`;
  };

  return (
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
      <StatTile
        label="Seats allowed"
        value={seatsAllowed === null ? dash : number.format(seatsAllowed)}
        hint={seatsHint()}
        tone="b"
        icon={Users}
      />
      <StatTile
        label="Seats used"
        value={seatsLoading || !seats ? dash : number.format(seats.used)}
        hint={usedHint()}
        // Amber once the workspace is full: the next invite will be rejected, and
        // an admin should see that before they try.
        tone={seats?.remaining === 0 ? 'y' : 'g'}
        icon={UserCheck}
      />
      <StatTile
        label="Team miles (MTD)"
        value={
          mileageLoading || !mileage
            ? dash
            : miles.format(mileage.monthToDate.miles)
        }
        hint={
          mileageLoading || !mileage
            ? 'Loading…'
            : `${miles.format(mileage.weekToDate.miles)} miles this week`
        }
        tone="b"
        icon={Route}
      />
      <StatTile
        label="Team reimbursement (MTD)"
        value={
          mileageLoading || !mileage
            ? dash
            : currency.format(mileage.monthToDate.reimbursement)
        }
        hint={
          mileageLoading || !mileage
            ? 'Loading…'
            : `${number.format(mileage.monthToDate.trips)} trip${
                mileage.monthToDate.trips === 1 ? '' : 's'
              } logged`
        }
        tone="gd"
        icon={Car}
      />
    </div>
  );
}
