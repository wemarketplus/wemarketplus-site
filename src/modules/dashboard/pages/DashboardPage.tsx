import { Card, CardContent } from '@/shared/ui/core';
import { OnboardingChecklistCard } from '@/modules/onboarding-checklist';
import { useRole, HL_MARKETING_ROLES, STAFF_ROLES } from '@/shared/rbac';
import { Product } from '@/shared/types';
import { MarketerDayPanel } from '../components/MarketerDayPanel';
import { DashboardActivityList } from '../components/DashboardActivityList';
import { DashboardPageHeader } from '../components/DashboardPageHeader';
import { DashboardStatTile } from '../components/DashboardStatTile';
import { useDashboardContext } from '../hooks/useDashboardContext';
import { useDashboardGreeting } from '../hooks/useDashboardGreeting';
import { useProductDashboard } from '../hooks/useProductDashboard';

export function DashboardPage() {
  const { greeting, name, role } = useDashboardGreeting();
  const { stats, activity, isLoading, isError } = useProductDashboard();
  const { product, tier, organizationName, period, hasActivePlan } =
    useDashboardContext();

  const { isAny } = useRole();
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

  return (
    <div className="space-y-8">
      <DashboardPageHeader
        greeting={greeting}
        name={name}
        role={role}
        product={product}
        tier={tier}
        organizationName={organizationName}
        period={period}
        hasActivePlan={hasActivePlan}
      />

      <OnboardingChecklistCard />

      {showMarketerDay && <MarketerDayPanel />}

      {isError ? (
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
