// Grant-CRM territories — API-only module (no page UI yet; scheduling page may
// consume this later).
export {
  territoriesApi,
  useListTerritoriesQuery,
  useGetTerritoryQuery,
  useCreateTerritoryMutation,
  useUpdateTerritoryMutation,
  useDeleteTerritoryMutation,
  useListUserTerritoriesQuery,
  useAssignUserTerritoriesMutation,
} from './api/territoriesApi';
export type {
  TerritoryRecord,
  CreateTerritoryRequest,
  UpdateTerritoryRequest,
} from './types/territoriesTypes';
export { TERRITORY_PRIORITY, type TerritoryPriority } from './constants/territoriesConstants';
