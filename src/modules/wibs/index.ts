// Grant-CRM Workforce Investment Boards — API-only module (no page UI yet).
export {
  wibsApi,
  useListWibsQuery,
  useListMyWibsQuery,
  useGetWibQuery,
  useCreateWibMutation,
  useUpdateWibMutation,
  useDeleteWibMutation,
  useSetWibTerritoryMutation,
  useGetWibViewQuery,
  useSetWibViewMutation,
} from './api/wibsApi';
export type {
  WibRecord,
  CreateWibRequest,
  UpdateWibRequest,
  ListWibsQuery,
  WibViewPref,
} from './types/wibsTypes';
export { WIB_STATUS, type WibStatus } from './constants/wibsConstants';
