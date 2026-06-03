import { ExecutiveDashboard } from './ExecutiveDashboard';
import { HousekeepingDashboard } from './HousekeepingDashboard';
import { MaintenanceDashboard } from './MaintenanceDashboard';
import { SalesDashboard } from './SalesDashboard';
import { useGoldDemo } from '../hooks/useGoldDemo';

// Reproduces rDash()'s role branching: the dashboard view varies by role
// (maintenance / housekeeping / marketer get focused dashboards; director and
// admin get the full executive dashboard).
export function DashboardTab() {
  const { role } = useGoldDemo();

  if (role === 'maintenance') return <MaintenanceDashboard />;
  if (role === 'housekeeping') return <HousekeepingDashboard />;
  if (role === 'marketer') return <SalesDashboard />;
  return <ExecutiveDashboard />;
}
