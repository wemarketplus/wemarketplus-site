// CommunityLink role-scoped dashboards.
//
// The guide gives every CommunityLink persona its own named home screen — Sales
// Dashboard, Executive Dashboard, Portfolio Dashboard, My Queue. This module owns
// those four and the role switch that chooses between them; the cross-product
// DashboardPage composes <ClDashboardPanel/> when the active product is
// CommunityLink and keeps its own generic tiles for HospiceLink.
//
// No API slice of its own: every figure is derived from the cl/* list endpoints
// the operations, leads, tours and referrals modules already expose. See
// utils/clDashboardMetrics for the derivations and their sampling caveat.
export { ClDashboardPanel } from './components/ClDashboardPanel';
export { ClSalesDashboard } from './components/ClSalesDashboard';
export { ClExecutiveDashboard } from './components/ClExecutiveDashboard';
export { ClPortfolioDashboard } from './components/ClPortfolioDashboard';
export { ClMyQueuePanel } from './components/ClMyQueuePanel';
export { ClCareDashboard } from './components/ClCareDashboard';
export { ClQueueRow } from './components/ClQueueRow';
export { useClSalesDashboard } from './hooks/useClSalesDashboard';
export { useClExecutiveDashboard } from './hooks/useClExecutiveDashboard';
export { useClPortfolioDashboard } from './hooks/useClPortfolioDashboard';
export { useClMyQueue } from './hooks/useClMyQueue';
export {
  CL_DASHBOARD_FETCH_LIMIT,
  CL_OPEN_LEAD_STAGES,
  clMonthlyRevenue,
  clOccupancySnapshot,
  clPendingReferralFees,
  formatClCurrency,
  formatClPercent,
  hotClLeads,
  isHotClLead,
  isOpenClHousekeeping,
  isOpenClLead,
  isOpenClMakeReady,
  isOpenClTicket,
  leadDisplayName,
  upcomingClTours,
} from './utils/clDashboardMetrics';
export type {
  ClOccupancySnapshot,
  ClPendingFees,
} from './utils/clDashboardMetrics';
