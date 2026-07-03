// Grant-CRM employer companies — full CRUD UI on the shared entity kit
// (@/shared/ui/entity). Mirrors modules/contacts; adds server-side filters +
// an admin dedup action.
export { CompaniesPage } from './pages/CompaniesPage';
export {
  companiesApi,
  useListCompaniesQuery,
  useGetCompanyQuery,
  useCreateCompanyMutation,
  useUpdateCompanyMutation,
  useDeleteCompanyMutation,
  useDedupCompaniesMutation,
} from './api/companiesApi';
export type {
  CompanyRecord,
  CreateCompanyRequest,
  UpdateCompanyRequest,
  ListCompaniesQuery,
} from './types/companiesTypes';
export { COMPANY_STATUS, type CompanyStatus } from './constants/companiesConstants';
