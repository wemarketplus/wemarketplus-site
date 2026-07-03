// Grant-CRM contracts — tenant-scoped contract records. Full CRUD UI built on
// the shared entity kit (@/shared/ui/entity). Delete is Admin/Owner-only.
export { ContractsPage } from './pages/ContractsPage';
export {
  contractsApi,
  useListContractsQuery,
  useGetContractQuery,
  useCreateContractMutation,
  useUpdateContractMutation,
  useDeleteContractMutation,
} from './api/contractsApi';
export type {
  ContractRecord,
  CreateContractRequest,
  UpdateContractRequest,
  ListContractsQuery,
} from './types/contractsTypes';
export { CONTRACT_STATUS, type ContractStatus } from './constants/contractsConstants';
