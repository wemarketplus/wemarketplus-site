import { Card, CardContent } from '@/shared/ui/core';
import { OnboardingChecklistCard } from '@/modules/onboarding-checklist';
import { DashboardActivityList } from '../components/DashboardActivityList';
import { DashboardPageHeader } from '../components/DashboardPageHeader';
import { DashboardStatTile } from '../components/DashboardStatTile';
import { useDashboardContext } from '../hooks/useDashboardContext';
import { useDashboardGreeting } from '../hooks/useDashboardGreeting';
import { useProductDashboard } from '../hooks/useProductDashboard';

export function DashboardPage() {
  const { greeting, name, role } = useDashboardGreeting();
  const { stats, activity, isLoading, isError } = useProductDashboard();
  const { product, tier, organizationName, period } = useDashboardContext();

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
      />

      <OnboardingChecklistCard />

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
            {stats.map((stat) => (
              <DashboardStatTile key={stat.id} stat={stat} />
            ))}
          </div>

          <DashboardActivityList items={activity} />
        </>
      )}
    </div>
  );
}
