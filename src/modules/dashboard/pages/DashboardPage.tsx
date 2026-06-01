import { DashboardActivityList } from '../components/DashboardActivityList';
import { DashboardPageHeader } from '../components/DashboardPageHeader';
import { DashboardStatTile } from '../components/DashboardStatTile';
import { useDashboardContext } from '../hooks/useDashboardContext';
import { useDashboardGreeting } from '../hooks/useDashboardGreeting';
import { useProductDashboard } from '../hooks/useProductDashboard';

export function DashboardPage() {
  const { greeting, name, role } = useDashboardGreeting();
  const { stats, activity } = useProductDashboard();
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

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        {stats.map((stat) => (
          <DashboardStatTile key={stat.id} stat={stat} />
        ))}
      </div>

      <DashboardActivityList items={activity} />
    </div>
  );
}
