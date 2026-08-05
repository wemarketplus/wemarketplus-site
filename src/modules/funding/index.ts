// DEPRECATED — NOT NEEDED, PENDING REMOVAL.
// Funding is one of the three Grants modules (Funding / Applications /
// Agreements). Removed from the sidebar on 2026-08-06 per the product owner;
// the whole Grants domain is slated to be removed/purged from FE and BE. The
// code is kept only so the section can be restored quickly if it turns out to
// be needed. Do NOT build new features on this module or wire it into new
// screens.
//
// Grant-CRM funding opportunities — full CRUD UI on the shared entity kit.
export { FundingPage } from './pages/FundingPage';
export {
  fundingApi,
  useListFundingQuery,
  useGetFundingQuery,
  useCreateFundingMutation,
  useUpdateFundingMutation,
  useDeleteFundingMutation,
} from './api/fundingApi';
export type {
  FundingRecord,
  CreateFundingRequest,
  UpdateFundingRequest,
  ListFundingQuery,
} from './types/fundingTypes';
export { FUNDING_STATUS, type FundingStatus } from './constants/fundingConstants';
