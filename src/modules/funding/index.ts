// Grant-CRM funding opportunities — API-only module (no page UI yet).
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
