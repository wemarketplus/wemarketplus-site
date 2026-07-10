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
