// Public surface of the dashboard module.
export { DashboardPage } from './pages/DashboardPage';
export { default as dashboardReducer } from './store/dashboardSlice';
export { reportsApi, useGetReportSummaryQuery } from './api/reportsApi';
export { dashboardApi, useGetDashboardSummaryQuery } from './api/dashboardApi';
export { reportPdfUrl } from './utils/reportPdfUrl';
export type {
  ReportSummary,
  ReportTotals,
  ReportRevenue,
  ReportRecentActivity,
  ReportTopWib,
} from './types/reportsTypes';
export type { DashboardSummary, DashboardSummaryActivity } from './types/dashboardTypes';
