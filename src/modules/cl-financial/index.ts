export { ClFinancialPage } from './pages/ClFinancialPage';
export { default as clFinancialReducer } from './store/clFinancialSlice';
export {
  clFinancialApi,
  useListClRevenueQuery,
  useCreateClRevenueMutation,
  useUpdateClRevenueMutation,
  useDeleteClRevenueMutation,
  useListClConcessionsQuery,
  useCreateClConcessionMutation,
  useUpdateClConcessionMutation,
  useDeleteClConcessionMutation,
  useListClCompetitorsQuery,
  useCreateClCompetitorMutation,
  useDeleteClCompetitorMutation,
  useListClLocPricingQuery,
  useCreateClLocPricingMutation,
  useDeleteClLocPricingMutation,
} from './api/clFinancialApi';
