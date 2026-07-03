// Public surface of the owner-portal module.
export { OwnerLayout } from './components/OwnerLayout';
export { OwnerDashboardPage } from './pages/OwnerDashboardPage';
export { OwnerRevenuePage } from './pages/OwnerRevenuePage';
export { OwnerCustomersPage } from './pages/OwnerCustomersPage';
export { OwnerPipelinePage } from './pages/OwnerPipelinePage';
export { OwnerVisitorsPage } from './pages/OwnerVisitorsPage';
export { OwnerMarketingPage } from './pages/OwnerMarketingPage';
export { OwnerChurnPage } from './pages/OwnerChurnPage';
export { OwnerUsagePage } from './pages/OwnerUsagePage';
export { OwnerInsightsPage } from './pages/OwnerInsightsPage';
export { OwnerCommunicationPage } from './pages/OwnerCommunicationPage';
export { OwnerSecurityPage } from './pages/OwnerSecurityPage';
export { OwnerAdminControlsPage } from './pages/OwnerAdminControlsPage';
export { default as ownerPortalReducer } from './store/ownerPortalSlice';
export {
  ownerPortalApi,
  useGetOwnerMetricsQuery,
  useListOwnerCustomersQuery,
  useSuspendCustomerMutation,
  useListPipelineQuery,
  useGetPipelineRecordQuery,
  useCreatePipelineRecordMutation,
  useUpdatePipelineRecordMutation,
  useDeletePipelineRecordMutation,
} from './api/ownerPortalApi';

// SuperAdmin tenant impersonation (support login into a customer workspace).
export { ImpersonationBanner } from './components/ImpersonationBanner';
export { useImpersonation } from './hooks/useImpersonation';
export {
  impersonationApi,
  useStartImpersonationMutation,
  useStopImpersonationMutation,
} from './api/impersonationApi';
