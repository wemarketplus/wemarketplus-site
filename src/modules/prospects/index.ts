export { ProspectsPage } from './pages/ProspectsPage';
export { ReengagementPage } from './pages/ReengagementPage';
export { default as prospectsReducer } from './store/prospectsSlice';
export {
  prospectsApi,
  useListProspectsQuery,
  useGetProspectQuery,
  useCreateProspectMutation,
  useUpdateProspectMutation,
  useDeleteProspectMutation,
} from './api/prospectsApi';
export { mapProspectRecord } from './utils/prospectsUtils';
