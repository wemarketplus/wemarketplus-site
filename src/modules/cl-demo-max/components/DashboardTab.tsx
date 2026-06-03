import { ExecutiveDashboard } from './ExecutiveDashboard';
import { HousekeepingDashboard } from './HousekeepingDashboard';
import { MaintenanceDashboard } from './MaintenanceDashboard';
import { OwnerDashboard } from './OwnerDashboard';
import { SalesAdmissionsDashboard } from './SalesAdmissionsDashboard';
import { SalesDashboard } from './SalesDashboard';
import { useMaxDemo } from '../hooks/useMaxDemo';

// Reproduces rDash()'s role branching across all seven Max roles.
export function DashboardTab() {
  const { role } = useMaxDemo();
  if (role === 'salesadmissions') return <SalesAdmissionsDashboard />;
  if (role === 'maintenance') return <MaintenanceDashboard />;
  if (role === 'housekeeping') return <HousekeepingDashboard />;
  if (role === 'marketer') return <SalesDashboard />;
  if (role === 'owner') return <OwnerDashboard />;
  return <ExecutiveDashboard />;
}
