// DEPRECATED — NOT NEEDED, PENDING REMOVAL.
// Agreements is one of the three Grants modules (Funding / Applications /
// Agreements). Removed from the sidebar on 2026-08-06 per the product owner;
// the whole Grants domain is slated to be removed/purged from FE and BE. The
// code is kept only so the section can be restored quickly if it turns out to
// be needed. Do NOT build new features on this module or wire it into new
// screens.
//
// NOTE when purging: this module also exports the *contracts* hooks below, and
// Contracts (Financial > /contracts) is a live, kept module. Contracts has its
// own api slice (@/modules/contracts/api/contractsApi) — the contract exports
// here are unused duplicates, so check before deleting either.
//
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
