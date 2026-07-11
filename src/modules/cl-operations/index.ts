export { ClOperationsPage } from './pages/ClOperationsPage';
export { default as clOperationsReducer } from './store/clOperationsSlice';
export {
  clOperationsApi,
  useListClCommunitiesQuery,
  useCreateClCommunityMutation,
  useListClApartmentsQuery,
  useCreateClApartmentMutation,
  useUpdateClApartmentMutation,
  useDeleteClApartmentMutation,
  useListClMakeReadyQuery,
  useCreateClMakeReadyMutation,
  useUpdateClMakeReadyMutation,
  useDeleteClMakeReadyMutation,
  useListClMaintenanceQuery,
  useCreateClMaintenanceMutation,
  useUpdateClMaintenanceMutation,
  useDeleteClMaintenanceMutation,
  useListClHousekeepingQuery,
  useCreateClHousekeepingMutation,
  useUpdateClHousekeepingMutation,
  useDeleteClHousekeepingMutation,
} from './api/clOperationsApi';
