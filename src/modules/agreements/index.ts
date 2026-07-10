// Grant-CRM agreements + contracts — agreements CRUD UI on the shared entity kit.
export { AgreementsPage } from './pages/AgreementsPage';
export {
  agreementsApi,
  useListAgreementsQuery,
  useGetAgreementStatsQuery,
  useCreateAgreementMutation,
  useUpdateAgreementMutation,
  useDeleteAgreementMutation,
  useListContractsQuery,
  useCreateContractMutation,
  useUpdateContractMutation,
  useDeleteContractMutation,
} from './api/agreementsApi';
export type {
  AgreementRecord,
  AgreementStats,
  CreateAgreementRequest,
  ContractRecord,
  CreateContractRequest,
} from './types/agreementsTypes';
export {
  AGREEMENT_STATUS,
  CONTRACT_STATUS,
  type AgreementStatus,
  type ContractStatus,
} from './constants/agreementsConstants';
