import { SECTION_TITLE } from '@/shared/ui/core/typography';
import { CreditCard, UserCheck, UserPlus } from 'lucide-react';
import { Link } from 'react-router-dom';
import { AddUserModal, useAddUser } from '@/modules/users';
import { Button, Card, CardContent } from '@/shared/ui/core';
import { StatTile } from '@/shared/ui/data-display';
import { useAccountPlan } from '../hooks/useAccountPlan';

/**
 * Steps 3 and 4 of the Administrator's Account Settings flow, on the same tab as
 * step 2: the plan and its seat count, and the button that adds a team member.
 *
 * WHY HERE AND NOT ONLY ON /users. The Team page already carries seat tiles and
 * an invite (TeamOverviewStats + UsersPage), and this does NOT reimplement
 * either — it reads the same GET /users/seats and drives the same `useAddUser` +
 * `AddUserModal`. The guide sends an administrator to Settings for all four
 * steps of "keep the account running", and sending them to a second screen for
 * two of them is the kind of split the guide is written to avoid.
 *
 * ADMIN-GATED BY ITS CALLER, not here: /users/seats is Admin/Owner-only
 * server-side, and Settings additionally admits CommunityLink's Owner/Investor,
 * who would otherwise fire a 403 on every visit. SettingsPage wraps this in the
 * same RoleGate UsersPage uses.
 */
export function AccountPlanCard() {
  const {
    planLabel,
    billingPlanName,
    used,
    allowed,
    remaining,
    hasSeatLimit,
    atLimit,
    enforced,
    isLoading,
  } = useAccountPlan();
  const invite = useAddUser();

  // A dash rather than a zero while loading: "0 seats used" is a claim, and a
  // wrong one that resolves a moment later reads as a glitch. Same rule as
  // TeamOverviewStats.
  const dash = '—';

  const seatsValue = () => {
    if (isLoading || used === null) return dash;
    return hasSeatLimit ? `${used} / ${allowed}` : String(used);
  };

  const seatsHint = () => {
    if (isLoading || used === null) return 'Loading…';
    if (!hasSeatLimit) {
      // assertSeatAvailable fails open on an unrecognised plan, so there is
      // genuinely no cap to report — say so rather than implying unlimited.
      return 'No seat limit is configured for this plan.';
    }
    if (atLimit) return 'All seats are in use — upgrade to add more users.';
    return `${remaining} seat${remaining === 1 ? '' : 's'} remaining`;
  };

  return (
    <Card>
      <CardContent className="space-y-5 px-6 py-6">
        <header className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className={SECTION_TITLE}>
              Plan &amp; seats
            </h2>
            <p className="mt-1 text-sm text-muted">
              Your subscription and how much of it your team is using.
            </p>
          </div>
          <Button size="sm" onClick={invite.openModal}>
            <UserPlus className="h-4 w-4" />
            Invite user
          </Button>
        </header>

        <div className="grid gap-4 sm:grid-cols-2">
          <StatTile
            label="Subscription plan"
            value={planLabel}
            hint={
              // Seats are billed ONCE per tenant against the subscription, not
              // per product dashboard — so a dual-product tenant can legitimately
              // see a different plan name here. Naming it "billing plan" makes
              // that read as intentional rather than as the wrong plan.
              billingPlanName
                ? `Billing plan: ${billingPlanName}`
                : 'Your current plan for this dashboard.'
            }
            tone="gd"
            icon={CreditCard}
          />
          <StatTile
            label="Seats used"
            value={seatsValue()}
            hint={seatsHint()}
            // Amber once the workspace is full: the next invite will be
            // rejected, and an admin should see that before they try.
            tone={atLimit ? 'y' : 'g'}
            icon={UserCheck}
          />
        </div>

        {atLimit && enforced && (
          <p className="text-xs text-warning">
            Adding another user will be rejected until you free a seat or move to
            a larger plan.
          </p>
        )}

        <Link
          to="/billing"
          className="inline-block rounded-pill border border-border/[0.12] px-3 py-1.5 text-xs font-semibold text-foreground transition-colors hover:border-primary/40 hover:text-primary"
        >
          Manage subscription
        </Link>
      </CardContent>

      <AddUserModal
        open={invite.open}
        isSaving={invite.isSaving}
        submitError={invite.submitError}
        onClose={invite.close}
        onSubmit={invite.submit}
      />
    </Card>
  );
}
