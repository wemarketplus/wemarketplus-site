// Grant-CRM employer companies — API-only module (no page UI yet).
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
