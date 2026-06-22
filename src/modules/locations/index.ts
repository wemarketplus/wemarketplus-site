// Grant-CRM employer locations — API-only module (no page UI yet).
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
export { LOCATION_STATUS, type LocationStatus } from './constants/locationsConstants';
