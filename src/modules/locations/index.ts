// Grant-CRM employer locations — full CRUD UI on the shared entity kit.
export { LocationsPage } from './pages/LocationsPage';
export {
  locationsApi,
  useListLocationsQuery,
  useGetLocationQuery,
  useCreateLocationMutation,
  useUpdateLocationMutation,
  useDeleteLocationMutation,
} from './api/locationsApi';
export type {
  LocationRecord,
  CreateLocationRequest,
  UpdateLocationRequest,
  ListLocationsQuery,
} from './types/locationsTypes';
export {
  LOCATION_STATUS,
  LOCATION_STATUS_LABELS,
  type LocationStatus,
} from './constants/locationsConstants';
