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
