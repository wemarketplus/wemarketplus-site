// Grant-CRM territories — full CRUD UI on the shared entity kit.
export { TerritoriesPage } from './pages/TerritoriesPage';
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
export {
  TERRITORY_PRIORITY,
  TERRITORY_PRIORITY_LABELS,
  type TerritoryPriority,
} from './constants/territoriesConstants';
