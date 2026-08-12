import { Card, CardContent } from '@/shared/ui/core';
import { ClDashboardPanel } from '@/modules/cl-dashboard';
import { OnboardingChecklistCard } from '@/modules/onboarding-checklist';
import {
  useRole,
  ADMIN_ONLY,
  CL_MANAGEMENT_ROLES,
  HL_MARKETING_ROLES,
  STAFF_ROLES,
} from '@/shared/rbac';
import { Product } from '@/shared/types';
import { MarketerDayPanel } from '../components/MarketerDayPanel';
import { DashboardActivityList } from '../components/DashboardActivityList';
import { DashboardPageHeader } from '../components/DashboardPageHeader';
import { DashboardStatTile } from '../components/DashboardStatTile';
import { useDashboardContext } from '../hooks/useDashboardContext';
import { useDashboardGreeting } from '../hooks/useDashboardGreeting';
import { useProductDashboard } from '../hooks/useProductDashboard';

export function DashboardPage() {
  const { greeting, name, role, title } = useDashboardGreeting();
  const { product, tier, organizationName, period, hasActivePlan } =
    useDashboardContext();
  const { isAny } = useRole();

  const isCommunity = product === Product.CommunityLink;
  /**
   * CommunityLink management still shows the tenant audit feed, which rides on
   * the same summary payload — so the request is kept for them and dropped only
   * where nothing on the screen consumes it.
   *
   * That is the two CommunityLink FIELD roles: their screen is "My Queue" (their
   * own assigned work, fetched by @/modules/cl-dashboard) with no tiles and no
   * feed, and /dashboard/summary aggregates prospects, invoices and the audit log
   * — resources a Maintenance or Housekeeping user is not entitled to read. Before
   * this, their dashboard fired a request that could only 403 and rendered nothing
   * from it either way.
   */
  const skipTenantSummary = isCommunity && !isAny(CL_MANAGEMENT_ROLES);
  const { stats, activity, isLoading, isError } = useProductDashboard({
    skip: skipTenantSummary,
  });
  // A HospiceLink field user opens the day on their OWN numbers: weekly pacing
  // and what needs them today. The tenant roll-up below stays for everyone.
  const showMarketerDay =
    product === Product.HospiceLink && isAny(HL_MARKETING_ROLES);
  // Overdue invoices is a Financial figure a field user cannot open, let alone
  // act on — the Financial group is staff-only. Showing it made a quarter of
  // their dashboard a dead number.
  const visibleStats = isAny(STAFF_ROLES)
    ? stats
    : stats.filter((stat) => stat.id !== 'overdue-invoices');
  /**
   * The getting-started checklist is WORKSPACE SETUP — invite the team, import
   * prospects, finish billing — so it belongs to whoever administers the tenant.
   *
   * Gated because it was not merely irrelevant to a field persona but broken for
   * one: the checklist derives its steps from the prospects, users and tenant
   * lists, all of which answer 403 to a Nurse or Caregiver. Their dashboard fired
   * three forbidden requests on every load and rendered a checklist of steps they
   * are not allowed to complete.
   */
  const showOnboardingChecklist = isAny(ADMIN_ONLY);

  return (
    <div className="space-y-8">
      <DashboardPageHeader
        greeting={greeting}
        name={name}
        role={role}
        title={title}
        product={product}
        tier={tier}
        organizationName={organizationName}
        period={period}
        hasActivePlan={hasActivePlan}
      />

      {showOnboardingChecklist && <OnboardingChecklistCard />}

      {showMarketerDay && <MarketerDayPanel />}

      {isCommunity ? (
        <>
          <ClDashboardPanel />
          {/*
            The tenant-wide audit feed, for oversight roles only.
            A Maintenance or Housekeeping user's screen is "My Queue" — their own
            assigned work — and appending every lead edit and unit change made by
            the whole community turns that into a firehose of rows they cannot act
            on. CL_MANAGEMENT_ROLES is the group whose job the feed actually is.
          */}
          {isAny(CL_MANAGEMENT_ROLES) && <DashboardActivityList items={activity} />}
        </>
      ) : isError ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            We could not load your dashboard right now. Please try again in a
            moment.
          </CardContent>
        </Card>
      ) : isLoading ? (
        <Card>
          <CardContent className="px-6 py-8 text-sm text-muted">
            Loading your dashboard…
          </CardContent>
        </Card>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            {visibleStats.map((stat) => (
              <DashboardStatTile key={stat.id} stat={stat} />
            ))}
          </div>

          <DashboardActivityList items={activity} />
        </>
      )}
    </div>
  );
}
