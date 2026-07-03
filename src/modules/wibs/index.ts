// Grant-CRM Workforce Investment Boards — CRUD UI on the shared entity kit.
export { WibsPage } from './pages/WibsPage';
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
