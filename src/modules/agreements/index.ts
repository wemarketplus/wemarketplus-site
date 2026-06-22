// Grant-CRM agreements + contracts — API-only module (no page UI yet).
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
